#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
缓存管理器实现模块
提供文件缓存和内存缓存支持,用于增量分析
"""

import json
import hashlib
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any

from ..core.interfaces import ICacheManager, AnalysisResult
import logging

logger = logging.getLogger(__name__)


class FileCacheManager(ICacheManager):
    """文件缓存管理器"""

    def __init__(self, cache_dir: str = "./cache", ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl = ttl  # 缓存有效期（秒）
        self._memory_cache: Dict[str, AnalysisResult] = {}
        # 添加文件锁机制,防止并发访问冲突
        self._file_locks: Dict[str, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def get_cached_result(self, file_hash: str) -> Optional[AnalysisResult]:
        """获取缓存的分析结果"""
        # 先检查内存缓存
        if file_hash in self._memory_cache:
            return self._memory_cache[file_hash]

        # 检查文件缓存
        cache_file = self._get_cache_file_path(file_hash)
        if not cache_file.exists():
            return None

        try:
            # 检查缓存是否过期
            if self._is_cache_expired(cache_file):
                self._remove_cache_file(file_hash)
                return None

            # 读取缓存数据
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            # 反序列化分析结果
            result = self._deserialize_result(cache_data)

            # 存入内存缓存
            self._memory_cache[file_hash] = result

            return result

        except Exception:
            # 如果缓存读取失败,删除缓存文件
            self._remove_cache_file(file_hash)
            return None

    def _get_file_lock(self, file_hash: str) -> threading.Lock:
        """获取文件特定的锁"""
        with self._global_lock:
            if file_hash not in self._file_locks:
                self._file_locks[file_hash] = threading.Lock()
            return self._file_locks[file_hash]

    def cache_result(self, file_hash: str, result: AnalysisResult) -> None:
        """缓存分析结果 - 线程安全版本"""
        # 存入内存缓存
        self._memory_cache[file_hash] = result

        # 获取文件特定锁
        file_lock = self._get_file_lock(file_hash)

        # 使用文件锁防止并发写入冲突
        with file_lock:
            try:
                cache_file = self._get_cache_file_path(file_hash)
                cache_file.parent.mkdir(parents=True, exist_ok=True)

                # 序列化分析结果
                cache_data = self._serialize_result(result)
                cache_data['_timestamp'] = time.time()
                cache_data['_ttl'] = self.ttl

                # 使用临时文件和原子重命名避免并发写入问题
                temp_file = cache_file.with_suffix('.tmp')

                try:
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        json.dump(cache_data, f, indent=2, ensure_ascii=False)

                    # 原子重命名,确保缓存文件始终处于一致状态
                    if temp_file.exists():
                        if cache_file.exists():
                            cache_file.unlink()
                        temp_file.rename(cache_file)

                except Exception:
                    # 清理临时文件
                    if temp_file.exists():
                        try:
                            temp_file.unlink()
                        except Exception:
                            pass
                    raise

                logger.debug(f"缓存文件写入成功: {cache_file}")

            except Exception as e:
                logger.warning(f"文件缓存写入失败 {file_hash}: {e}")
                # 文件缓存失败不影响主流程

    def is_cache_valid(self, file_path: Path, file_hash: str) -> bool:
        """检查缓存是否有效 - 基于文件内容哈希的验证"""
        # 检查文件是否存在
        if not file_path.exists():
            return False

        # 检查缓存是否存在
        cached_result = self.get_cached_result(file_hash)
        if cached_result is None:
            return False

        # 计算文件内容的实际哈希值
        try:
            current_file_hash = self._calculate_file_hash(file_path)

            # 如果文件内容哈希值不匹配,说明文件已被修改,缓存无效
            if current_file_hash != file_hash:
                logger.debug(f"文件内容已修改,缓存无效: {file_path}")
                return False

            # 检查缓存是否过期（基于时间）
            cache_file = self._get_cache_file_path(file_hash)
            if cache_file.exists():
                cache_age = time.time() - cache_file.stat().st_mtime
                if cache_age > self.ttl:
                    logger.debug(f"缓存已过期：{file_path}")
                    return False

            return True

        except Exception as e:
            logger.warning(f"缓存验证失败 {file_path}: {e}")
            return False

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件内容的SHA-256哈希值"""
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
                return hashlib.sha256(file_content).hexdigest()
        except Exception as e:
            logger.error(f"计算文件哈希失败 {file_path}: {e}")
            return ""  # 返回空字符串表示计算失败

    def clear_cache(self) -> None:
        """清空缓存"""
        # 清空内存缓存
        self._memory_cache.clear()

        # 清空文件缓存
        try:
            import shutil
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(exist_ok=True)
        except Exception:
            pass

    def cleanup_expired_cache(self) -> int:
        """清理过期的缓存文件,返回清理的文件数量"""
        cleaned_count = 0

        try:
            if not self.cache_dir.exists():
                return 0

            current_time = time.time()

            for cache_file in self.cache_dir.rglob("*.json"):
                try:
                    # 检查文件是否过期
                    file_age = current_time - cache_file.stat().st_mtime
                    if file_age > self.ttl:
                        cache_file.unlink()
                        cleaned_count += 1
                except Exception:
                    continue

        except Exception:
            pass

        return cleaned_count

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        stats = {
            "memory_cache_size": len(self._memory_cache),
            "cache_dir": str(self.cache_dir),
            "ttl": self.ttl,
        }

        try:
            # 计算文件缓存大小
            if self.cache_dir.exists():
                cache_files = list(self.cache_dir.rglob("*.json"))
                stats["file_cache_count"] = len(cache_files)
                stats["total_cache_size"] = sum(f.stat().st_size for f in cache_files)
                stats["cache_dir_size"] = self._get_dir_size(self.cache_dir)
            else:
                stats["file_cache_count"] = 0
                stats["total_cache_size"] = 0
                stats["cache_dir_size"] = 0

        except Exception:
            stats["file_cache_count"] = 0
            stats["total_cache_size"] = 0
            stats["cache_dir_size"] = 0

        return stats

    def _get_cache_file_path(self, file_hash: str) -> Path:
        """获取缓存文件路径"""
        # 使用哈希值的前2位作为子目录,避免单个目录文件过多
        subdir = file_hash[:2]
        cache_subdir = self.cache_dir / subdir
        cache_subdir.mkdir(exist_ok=True)
        return cache_subdir / f"{file_hash}.json"

    def _is_cache_expired(self, cache_file: Path) -> bool:
        """检查缓存是否过期"""
        try:
            current_time = time.time()
            file_age = current_time - cache_file.stat().st_mtime
            return file_age > self.ttl
        except Exception:
            return True

    def _remove_cache_file(self, file_hash: str) -> None:
        """删除缓存文件"""
        try:
            cache_file = self._get_cache_file_path(file_hash)
            if cache_file.exists():
                cache_file.unlink()
        except Exception:
            pass

    def _serialize_result(self, result: AnalysisResult) -> Dict[str, Any]:
        """序列化分析结果"""
        return {
            "file_path": result.file_path,
            "file_size": result.file_size,
            "analysis_status": result.analysis_status,
            "vulnerabilities": [
                {
                    "type": v.type,
                    "severity": v.severity.value,
                    "line": v.line,
                    "description": v.description,
                    "remediation": v.remediation,
                    "code_snippet": v.code_snippet,
                    "confidence": v.confidence,
                    "cwe_id": v.cwe_id,
                    "owasp_category": v.owasp_category
                }
                for v in result.vulnerabilities
            ],
            "security_score": result.security_score,
            "recommendations": result.recommendations,
            "analysis_time": result.analysis_time,
            "pre_analysis_info": result.pre_analysis_info
        }

    def _deserialize_result(self, data: Dict[str, Any]) -> AnalysisResult:
        """反序列化分析结果"""
        from ..core.interfaces import SeverityLevel, Vulnerability

        vulnerabilities = []
        for vuln_data in data.get("vulnerabilities", []):
            vulnerability = Vulnerability(
                type=vuln_data["type"],
                severity=SeverityLevel(vuln_data["severity"]),
                line=vuln_data["line"],
                description=vuln_data["description"],
                remediation=vuln_data["remediation"],
                code_snippet=vuln_data["code_snippet"],
                confidence=vuln_data.get("confidence", 0.8),
                cwe_id=vuln_data.get("cwe_id"),
                owasp_category=vuln_data.get("owasp_category")
            )
            vulnerabilities.append(vulnerability)

        return AnalysisResult(
            file_path=data["file_path"],
            file_size=data["file_size"],
            analysis_status=data["analysis_status"],
            vulnerabilities=vulnerabilities,
            security_score=data["security_score"],
            recommendations=data["recommendations"],
            analysis_time=data["analysis_time"],
            pre_analysis_info=data.get("pre_analysis_info")
        )

    def _get_dir_size(self, path: Path) -> int:
        """获取目录大小"""
        try:
            total_size = 0
            for item in path.rglob("*"):
                if item.is_file():
                    total_size += item.stat().st_size
            return total_size
        except Exception:
            return 0


class MemoryCacheManager(ICacheManager):
    """内存缓存管理器"""

    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, tuple[AnalysisResult, float]] = {}

    def get_cached_result(self, file_hash: str) -> Optional[AnalysisResult]:
        """获取缓存的分析结果"""
        if file_hash not in self._cache:
            return None

        result, timestamp = self._cache[file_hash]
        current_time = time.time()

        # 检查是否过期
        if current_time - timestamp > self.ttl:
            del self._cache[file_hash]
            return None

        return result

    def cache_result(self, file_hash: str, result: AnalysisResult) -> None:
        """缓存分析结果"""
        current_time = time.time()

        # 如果缓存已满,清理最旧的条目
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        self._cache[file_hash] = (result, current_time)

    def is_cache_valid(self, file_path: Path, file_hash: str) -> bool:
        """检查缓存是否有效"""
        # 内存缓存只检查是否存在和过期
        result = self.get_cached_result(file_hash)
        return result is not None

    def clear_cache(self) -> None:
        """清空缓存"""
        self._cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        return {
            "cache_size": len(self._cache),
            "max_size": self.max_size,
            "ttl": self.ttl,
            "memory_usage": "low"  # 内存使用相对较低
        }