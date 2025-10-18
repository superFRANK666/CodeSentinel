#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
认证管理器模块
提供简单的认证和授权功能
"""

from typing import Optional, Dict, Any
from ..core.interfaces import IAuthenticationManager


class SimpleAuthManager(IAuthenticationManager):
    """简单的认证管理器实现"""

    def __init__(self):
        self._api_keys: Dict[str, Dict[str, Any]] = {}
        self._authenticated = False

    async def authenticate(self, api_key: str) -> bool:
        """验证API密钥"""
        # 简单的API密钥验证逻辑
        if api_key and len(api_key) > 10:
            self._authenticated = True
            return True
        return False

    def is_authenticated(self) -> bool:
        """检查是否已经认证"""
        return self._authenticated

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """获取用户信息"""
        if self._authenticated:
            return {"user_id": "default_user", "permissions": ["read", "analyze"], "rate_limit": 1000}
        return None

    def check_permission(self, permission: str) -> bool:
        """检查权限"""
        if not self._authenticated:
            return False

        user_info = self.get_user_info()
        if user_info and "permissions" in user_info:
            return permission in user_info["permissions"]
        return False

    def get_rate_limit(self) -> int:
        """获取速率限制"""
        user_info = self.get_user_info()
        if user_info and "rate_limit" in user_info:
            return user_info["rate_limit"]
        return 100  # 默认限制

    def validate_api_key_format(self, api_key: str) -> bool:
        """验证API密钥格式"""
        if not api_key:
            return False

        # 简单的格式验证：长度和字符类型
        if len(api_key) < 10:
            return False

        # 检查是否包含字母和数字
        has_letter = any(c.isalpha() for c in api_key)
        has_digit = any(c.isdigit() for c in api_key)

        return has_letter and has_digit

    def add_api_key(self, api_key: str, user_info: Dict[str, Any]) -> None:
        """添加API密钥（主要用于测试）"""
        self._api_keys[api_key] = user_info

    def remove_api_key(self, api_key: str) -> bool:
        """移除API密钥"""
        if api_key in self._api_keys:
            del self._api_keys[api_key]
            return True
        return False
