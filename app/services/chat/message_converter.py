# app/services/chat/message_converter.py

from abc import ABC, abstractmethod
import re
from typing import Any, Dict, List, Optional
import requests
import base64
import json
SUPPORTED_ROLES = ["user", "model", "system"]
IMAGE_URL_PATTERN = r'\[image\]\((.*?)\)'


class MessageConverter(ABC):
    """消息转换器基类"""

    @abstractmethod
    def convert(self, messages: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        pass

def _get_mime_type_and_data(base64_string):
    """
    从 base64 字符串中提取 MIME 类型和数据。
    
    参数:
        base64_string (str): 可能包含 MIME 类型信息的 base64 字符串
        
    返回:
        tuple: (mime_type, encoded_data)
    """
    # 检查字符串是否以 "data:" 格式开始
    if base64_string.startswith('data:'):
        # 提取 MIME 类型和数据
        pattern = r'data:([^;]+);base64,(.+)'
        match = re.match(pattern, base64_string)
        if match:
            mime_type = "image/jpeg" if match.group(1) == "image/jpg" else match.group(1)
            encoded_data = match.group(2)
            return mime_type, encoded_data
    
    # 如果不是预期格式，假定它只是数据部分
    return None, base64_string

def _convert_image(image_url: str) -> Dict[str, Any]:
    if image_url.startswith("http"):
        image_url = "data:image/png;base64," + _convert_image_to_base64(image_url)
    if image_url.startswith("data:image"):
        mime_type, encoded_data = _get_mime_type_and_data(image_url)
        return {
            "inline_data": {
                "mime_type": mime_type,
                "data": encoded_data
            }
        }
    return {
            "image_url": {
                "url": image_url
            }
        }


def _convert_image_to_base64(url: str) -> str:
    """
    将图片URL转换为base64编码
    Args:
        url: 图片URL
    Returns:
        str: base64编码的图片数据
    """
    response = requests.get(url)
    if response.status_code == 200:
        # 将图片内容转换为base64
        img_data = base64.b64encode(response.content).decode('utf-8')
        return img_data
    else:
        raise Exception(f"Failed to fetch image: {response.status_code}")


def _process_text_with_image(text: str) -> List[Dict[str, Any]]:
    """
    处理可能包含图片URL的文本，提取图片并转换为base64

    Args:
        text: 可能包含图片URL的文本

    Returns:
        List[Dict[str, Any]]: 包含文本和图片的部分列表
    """
    parts = []
    img_url_match = re.search(IMAGE_URL_PATTERN, text)
    if img_url_match:
        # 提取URL
        img_url = img_url_match.group(1)
        # 将URL对应的图片转换为base64
        try:
            base64_data = _convert_image_to_base64(img_url)
            parts.append({
                "inlineData": {
                    "mimeType": "image/png",
                    "data": base64_data
                }
            })
        except Exception:
            # 如果转换失败，回退到文本模式
            parts.append({"text": text})
    else:
        # 没有图片URL，作为纯文本处理
        parts.append({"text": text})
    return parts


class OpenAIMessageConverter(MessageConverter):
    """OpenAI消息格式转换器"""

    def convert(self, messages: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        converted_messages = []
        system_instruction_parts = []

        for idx, msg in enumerate(messages):
            role = msg.get("role", "")
            if role not in SUPPORTED_ROLES:
                if role == "tool":
                    role = "function"
                else:
                    # 如果是最后一条消息，则认为是用户消息
                    if idx == len(messages) - 1:
                        role = "user"
                    else:
                        role = "model"

            parts = []
            # 特别处理最后一个assistant的消息，按\n\n分割
            if role == "model" and idx == len(messages) - 2 and isinstance(msg["content"], str) and msg["content"]:
                # 按\n\n分割消息
                content_parts = msg["content"].split("\n\n")
                for part in content_parts:
                    if not part.strip():  # 跳过空内容
                        continue
                # 处理可能包含图片的文本
                parts.extend(_process_text_with_image(part))
                
            elif role == "model":
                tool_calls = msg.get("tool_calls", [])
                if tool_calls:
                    for tool_call in tool_calls:
                        args = tool_call.get("function").get("arguments")
                        # 判断是否为json字符串,如果不是则尝试转换
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except json.JSONDecodeError:
                                print(f"args is not a json string: {args}")
                                pass
                        parts.append({
                            "functionCall": {
                                "name": tool_call.get("function").get("name"),
                                "args": args
                            }
                        })
            elif role == "function":
                # 处理工具返回的消息 - Gemini格式为functionResponse
                # 先确保有name字段，如果没有则尝试使用tool_call_id
                function_name = msg.get("name") or msg.get("tool_call_id") or "unknown_function"
                # 转换为Gemini的functionResponse格式
                parts.append({
                    "functionResponse": {
                        "name": function_name,
                        "response": {
                            "content": {
                                "result": msg.get("content")
                            }
                        }
                    }
                })
            elif isinstance(msg["content"], str) and msg["content"]:
                # 请求 gemini 接口时如果包含 content 字段但内容为空时会返回 400 错误，所以需要判断是否为空并移除
                parts.extend(_process_text_with_image(msg["content"]))
            elif isinstance(msg["content"], list):
                for content in msg["content"]:
                    if isinstance(content, str) and content:
                        parts.append({"text": content})
                    elif isinstance(content, dict):
                        if content["type"] == "text" and content["text"]:
                            parts.append({"text": content["text"]})
                        elif content["type"] == "image_url":
                            parts.append(_convert_image(content["image_url"]["url"]))

            if parts:
                if role == "system":
                    system_instruction_parts.extend(parts)
                else:
                    converted_messages.append({"role": role, "parts": parts})

        system_instruction = (
            None
            if not system_instruction_parts
            else {
                "role": "system",
                "parts": system_instruction_parts,
            }
        )
        print(f"converted_messages: {converted_messages}")
        return converted_messages, system_instruction