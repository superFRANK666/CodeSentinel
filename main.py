#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI代码安全审计CLI工具 - 增强版主程序
集成依赖注入、配置管理、缓存、进度显示等高级功能
"""

import asyncio
import argparse
import logging
import sys
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

# 设置控制台编码
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 导入核心模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from src.core.container import get_container, initialize_container, cleanup_container
from src.core.interfaces import (
    ICodeAnalyzer, IReportGenerator, IConfigManager, ICacheManager,
    IProgressReporter, IErrorHandler, SeverityLevel, AppConfig, AnalysisResult
)
from src.core.analyzers.base_analyzer import BaseCodeAnalyzer
from src.infrastructure.progress_reporter import ProgressReporterFactory
from src.infrastructure.error_handler import create_error_handler
from src.application.report_generators import ReportGeneratorFactory
from src.infrastructure.ui_manager import UIManager, show_startup_banner, show_loading, clear_terminal
from src.infrastructure.ascii_art import CODESENTINEL_LOGO, SIMPLE_LOGO, STATUS_ICONS, create_gradient_text


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('security_audit.log', encoding='utf-8')
    ]
)

logger = logging.getLogger(__name__)


class SecurityAuditCLI:
    """增强版安全审计CLI工具"""

    def __init__(self):
        self.container = get_container()
        self.config_manager: Optional[IConfigManager] = None
        self.cache_manager: Optional[ICacheManager] = None
        self.progress_reporter: Optional[IProgressReporter] = None
        self.error_handler: Optional[IErrorHandler] = None
        self.app_config: Optional[AppConfig] = None

    async def initialize(self, config_path: Optional[str] = None) -> bool:
        """初始化应用程序"""
        try:
            logger.info("正在初始化安全审计工具...")

            # 加载配置
            await self._load_configuration(config_path)

            # 初始化依赖注入容器
            await initialize_container(self.app_config)

            # 获取组件实例
            self.config_manager = self.container.resolve(IConfigManager)
            self.cache_manager = self.container.resolve(ICacheManager)
            self.error_handler = self.container.resolve(IErrorHandler)

            logger.info("✅ 应用程序初始化成功")
            return True

        except Exception as e:
            logger.error(f"❌ 应用程序初始化失败: {e}")
            if self.error_handler:
                error_info = self.error_handler.handle_error(e, {"phase": "initialization"})
                self._display_error_info(error_info)
            return False

    async def _load_configuration(self, config_path: Optional[str] = None) -> None:
        """加载配置"""
        try:
            # 创建配置管理器
            if not self.container.is_registered(IConfigManager):
                from src.infrastructure.config_manager import JsonConfigManager
                self.container.register(IConfigManager, JsonConfigManager())
            self.config_manager = self.container.resolve(IConfigManager)

            # 加载配置
            config_dict = await self.config_manager.load_config(config_path)
            self.app_config = AppConfig(**config_dict)

            logger.info(f"配置加载成功: {config_path or '默认配置'}")

        except Exception as e:
            logger.warning(f"配置加载失败，使用默认配置: {e}")
            self.app_config = AppConfig()

    def _create_argument_parser(self) -> argparse.ArgumentParser:
        """创建参数解析器"""
        parser = argparse.ArgumentParser(
            description="AI代码安全审计CLI工具 v1.0 - 智能检测代码安全漏洞",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
示例用法:
  %(prog)s script.py                          # 分析单个Python文件
  %(prog)s app.js                             # 分析单个JavaScript文件
  %(prog)s src/                              # 分析整个目录（支持多语言）
  %(prog)s app.py --output report.md         # 导出Markdown报告
  %(prog)s *.js --format json --output result.json  # 导出JSON报告
  %(prog)s code/ --config custom.json        # 使用自定义配置
  %(prog)s test.py --analyzer local          # 使用本地分析器
  %(prog)s src/ --analyzer multi_language    # 使用多语言分析器
  %(prog)s src/ --progress --verbose         # 显示进度和详细信息
            """
        )

        # 位置参数 - 文件或目录路径
        parser.add_argument(
            'paths',
            nargs='+',
            help='要分析的文件或目录路径（支持Python和JavaScript）'
        )

        # 基本选项
        parser.add_argument(
            '-o', '--output',
            type=str,
            help='输出报告文件路径'
        )

        parser.add_argument(
            '-f', '--format',
            choices=['console', 'markdown', 'json', 'html', 'xml'],
            default='console',
            help='输出格式（默认：console）'
        )

        parser.add_argument(
            '--analyzer',
            choices=['local', 'ai', 'hybrid', 'multi_language'],
            default='multi_language',
            help='分析器类型（默认：multi_language）'
        )

        parser.add_argument(
            '--severity',
            choices=['low', 'medium', 'high', 'critical', 'all'],
            default='all',
            help='最低漏洞严重程度（默认：all）'
        )

        # 高级选项
        parser.add_argument(
            '--config',
            type=str,
            help='配置文件路径'
        )

        parser.add_argument(
            '--max-file-size',
            type=int,
            default=1024,
            help='最大文件大小限制（KB，默认：1024）'
        )

        parser.add_argument(
            '--exclude',
            nargs='+',
            default=[],
            help='排除的文件或目录模式（如：test_*.py, __pycache__）'
        )

        parser.add_argument(
            '--include',
            nargs='+',
            default=['*.py', '*.js', '*.jsx', '*.mjs', '*.cjs'],
            help='包含的文件模式（如：*.py, *.js, *.jsx等）'
        )

        # 缓存选项
        parser.add_argument(
            '--no-cache',
            action='store_true',
            help='禁用缓存机制'
        )

        parser.add_argument(
            '--clear-cache',
            action='store_true',
            help='清除缓存后退出'
        )

        # 并发选项
        parser.add_argument(
            '--workers',
            type=int,
            default=None,
            help='并发工作线程数（默认：自动）'
        )

        # 显示选项
        parser.add_argument(
            '--progress',
            action='store_true',
            help='显示进度条'
        )

        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='显示详细输出'
        )

        parser.add_argument(
            '--quiet', '-q',
            action='store_true',
            help='静默模式，只显示错误'
        )

        # 隐私选项
        parser.add_argument(
            '--privacy-mode',
            choices=['none', 'basic', 'full'],
            default='basic',
            help='隐私模式（默认：basic）'
        )

        # 其他选项
        parser.add_argument(
            '--version',
            action='version',
            version='%(prog)s 1.0.0'
        )

        return parser

    async def run_analysis(self, args: argparse.Namespace) -> bool:
        """运行安全分析"""
        try:
            logger.info("🚀 开始安全分析...")

            # 检查是否需要清除缓存
            if args.clear_cache:
                await self._clear_cache()
                return True

            # 设置进度报告器
            if args.progress:
                self.progress_reporter = ProgressReporterFactory.create_reporter("tqdm")
            else:
                self.progress_reporter = ProgressReporterFactory.create_reporter("silent")

            # 收集文件
            files = await self._collect_files(args)
            if not files:
                logger.warning("⚠️  未找到需要分析的文件")
                return False

            # 设置并发限制
            concurrent_limit = args.workers or self.app_config.analyzer.concurrent_limit

            # 运行分析
            results = await self._analyze_files(
                files, args, concurrent_limit
            )

            # 生成报告
            await self._generate_reports(results, args)

            logger.info("✅ 安全分析完成")
            return True

        except Exception as e:
            logger.error(f"❌ 安全分析失败: {e}")
            if self.error_handler:
                context = {
                    "phase": "analysis",
                    "args": vars(args),
                    "debug_mode": args.verbose
                }
                error_info = self.error_handler.handle_error(e, context)
                self._display_error_info(error_info)
            return False

    async def _collect_files(self, args: argparse.Namespace) -> List[Path]:
        """收集需要分析的文件"""
        try:
            if args.verbose:
                logger.info("📁 正在收集代码文件...")

            all_files = []
            exclude_patterns = args.exclude or self.app_config.security.blocked_patterns
            include_patterns = args.include
            max_file_size = args.max_file_size * 1024  # 转换为字节

            for path_str in args.paths:
                path = Path(path_str)

                if not path.exists():
                    logger.warning(f"⚠️  路径不存在: {path}")
                    continue

                if path.is_file():
                    # 单个文件
                    if self._should_include_file(path, include_patterns, exclude_patterns, max_file_size):
                        all_files.append(path)
                elif path.is_dir():
                    # 目录 - 递归查找
                    for pattern in include_patterns:
                        for file_path in path.rglob(pattern):
                            if self._should_include_file(file_path, include_patterns, exclude_patterns, max_file_size):
                                all_files.append(file_path)

            if args.verbose:
                logger.info(f"📊 找到 {len(all_files)} 个代码文件")

            return all_files

        except Exception as e:
            logger.error(f"文件收集失败: {e}")
            raise

    def _should_include_file(self, file_path: Path, include_patterns: List[str],
                           exclude_patterns: List[str], max_size: int) -> bool:
        """判断是否应该包含该文件"""
        try:
            # 检查文件大小
            if file_path.stat().st_size > max_size:
                logger.debug(f"文件过大，已跳过: {file_path}")
                return False

            # 检查排除模式
            file_str = str(file_path)
            for pattern in exclude_patterns:
                if self._match_pattern(file_str, pattern):
                    return False

            # 检查包含模式
            for pattern in include_patterns:
                if self._match_pattern(file_str, pattern):
                    return True

            return False

        except Exception:
            return False

    def _match_pattern(self, text: str, pattern: str) -> bool:
        """简单的模式匹配（支持*和?通配符）"""
        import fnmatch
        return fnmatch.fnmatch(text.lower(), pattern.lower())

    async def _analyze_files(self, files: List[Path], args: argparse.Namespace,
                           concurrent_limit: int) -> Dict[str, Any]:
        """分析文件"""
        try:
            # 获取分析器
            analyzer = self.container.resolve(ICodeAnalyzer, args.analyzer)
            severity_filter = self._parse_severity_level(args.severity)

            # 开始进度报告
            if self.progress_reporter:
                self.progress_reporter.start_progress(len(files), "代码安全分析")

            # 增量分析 - 检查缓存
            if self.cache_manager and not args.no_cache:
                files_to_analyze = await self._filter_cached_files(files)
            else:
                files_to_analyze = files

            if len(files_to_analyze) < len(files):
                logger.info(f"跳过 {len(files) - len(files_to_analyze)} 个已缓存文件")

            # 并发分析
            semaphore = asyncio.Semaphore(concurrent_limit)

            async def analyze_with_progress(file_path: Path) -> Dict[str, Any]:
                async with semaphore:
                    result = await analyzer.analyze_file(file_path, severity_filter)

                    # 缓存结果
                    if self.cache_manager and not args.no_cache:
                        file_hash = self._calculate_file_hash(file_path)
                        self.cache_manager.cache_result(file_hash, result)

                    # 更新进度
                    if self.progress_reporter:
                        self.progress_reporter.increment(1, f"分析完成: {file_path.name}")

                    return result

            # 分析所有文件
            if files_to_analyze:
                tasks = [analyze_with_progress(fp) for fp in files_to_analyze]
                analysis_results = await asyncio.gather(*tasks, return_exceptions=True)
            else:
                analysis_results = []

            # 获取缓存的结果
            cached_results = []
            if self.cache_manager and not args.no_cache:
                for file_path in files:
                    if file_path not in files_to_analyze:
                        file_hash = self._calculate_file_hash(file_path)
                        cached_result = self.cache_manager.get_cached_result(file_hash)
                        if cached_result:
                            cached_results.append(cached_result)
                            if self.progress_reporter:
                                self.progress_reporter.increment(1, f"使用缓存: {file_path.name}")

            # 合并结果
            all_results = []
            for result in analysis_results:
                if isinstance(result, Exception):
                    # 处理分析异常
                    logger.warning(f"文件分析异常: {result}")
                    continue
                all_results.append(result)

            all_results.extend(cached_results)

            # 完成进度
            if self.progress_reporter:
                self.progress_reporter.finish_progress()

            # 构建最终结果
            return self._build_analysis_results(all_results, files, args)

        except Exception as e:
            logger.error(f"文件分析失败: {e}")
            raise

    def _parse_severity_level(self, severity_str: str) -> SeverityLevel:
        """解析严重度级别"""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'all': SeverityLevel.LOW
        }
        return severity_map.get(severity_str, SeverityLevel.LOW)

    async def _filter_cached_files(self, files: List[Path]) -> List[Path]:
        """过滤已缓存的文件"""
        files_to_analyze = []

        for file_path in files:
            file_hash = self._calculate_file_hash(file_path)
            if not self.cache_manager.is_cache_valid(file_path, file_hash):
                files_to_analyze.append(file_path)

        return files_to_analyze

    def _calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希值 - 使用SHA-256算法"""
        import hashlib
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()  # 从MD5升级为SHA-256
                while chunk := f.read(8192):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception:
            return ""

    def _build_analysis_results(self, results: List[AnalysisResult],
                              files: List[Path], args: argparse.Namespace) -> Dict[str, Any]:
        """构建分析结果"""
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in results)
        files_with_issues = sum(1 for r in results if r.vulnerabilities)

        # 统计各严重度数量
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            for vuln in result.vulnerabilities:
                severity = vuln.severity.value
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            'scan_summary': {
                'total_files': len(files),
                'scan_time': 0,  # 将在外层计算
                'total_vulnerabilities': total_vulnerabilities,
                'severity_counts': severity_counts,
                'files_with_issues': files_with_issues,
                'analysis_engine': args.analyzer
            },
            'file_results': results
        }

    async def _generate_reports(self, results: Dict[str, Any], args: argparse.Namespace) -> None:
        """生成报告"""
        try:
            logger.debug(f"开始生成报告 - 格式: {args.format}, 输出: {args.output}")
            logger.debug(f"分析结果: {results}")

            # 获取报告生成器
            report_generator = ReportGeneratorFactory.create_report_generator(args.format)
            logger.debug(f"报告生成器创建成功: {type(report_generator)}")

            if args.output:
                # 生成文件报告
                logger.debug(f"生成文件报告到: {args.output}")
                report_generator.generate_report(results, args.output)
                logger.info(f"✅ 报告已生成: {args.output}")
                logger.debug(f"文件报告生成完成")
            else:
                # 控制台输出
                logger.debug("生成控制台报告")
                if args.format == 'console':
                    logger.debug("调用 generate_report")
                    report_generator.generate_report(results)
                    logger.debug("控制台报告生成完成")
                else:
                    # 对于非控制台格式，默认输出到标准输出
                    print(f"# 安全审计报告 ({args.format}格式)")
                    print(f"生成时间: {results.get('scan_summary', {}).get('scan_time', 0)}秒")
                    print(f"发现漏洞: {results.get('scan_summary', {}).get('total_vulnerabilities', 0)}个")

        except Exception as e:
            logger.error(f"报告生成失败: {e}")
            raise

    async def _clear_cache(self) -> None:
        """清除缓存"""
        try:
            if self.cache_manager:
                logger.info("🗑️  正在清除缓存...")
                self.cache_manager.clear_cache()
                cleaned_count = self.cache_manager.cleanup_expired_cache()
                logger.info(f"✅ 缓存清除完成，清理了 {cleaned_count} 个过期文件")
            else:
                logger.warning("缓存管理器未初始化")
        except Exception as e:
            logger.error(f"清除缓存失败: {e}")

    def _display_error_info(self, error_info: Dict[str, Any]) -> None:
        """显示错误信息"""
        print(f"\n❌ 错误类型: {error_info['error_type']}")
        print(f"❌ 错误信息: {error_info['error_message']}")
        print(f"ℹ️  友好提示: {error_info['friendly_message']}")
        print(f"🆔 错误ID: {error_info['error_id']}")

        if error_info['suggestions']:
            print("\n💡 解决建议:")
            for i, suggestion in enumerate(error_info['suggestions'], 1):
                print(f"   {i}. {suggestion}")

        if error_info.get('technical_details') and error_info['context'].get('debug_mode'):
            print("\n🔧 技术详情:")
            print(error_info['technical_details']['traceback'])

    async def cleanup(self) -> None:
        """清理资源"""
        try:
            logger.info("正在清理资源...")
            cleanup_container()
            logger.info("✅ 资源清理完成")
        except Exception as e:
            logger.error(f"资源清理失败: {e}")


async def main():
    """主函数"""
    # 显示启动界面
    ui_manager = UIManager()

    # 清屏并显示启动界面
    clear_terminal()
    ui_manager.show_startup_screen("1.0.0")

    # 显示Logo动画
    ui_manager.show_logo_animation()

    # 显示加载动画
    ui_manager.show_loading_animation("Initializing Security Engine", 2.0)

    cli = SecurityAuditCLI()

    try:
        # 解析参数
        parser = cli._create_argument_parser()
        args = parser.parse_args()

        # 处理静默模式
        if args.quiet:
            logging.getLogger().setLevel(logging.ERROR)
        elif args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # 初始化
        ui_manager.show_loading_animation("Loading Configuration", 1.0)
        if not await cli.initialize(args.config):
            sys.exit(1)

        # 运行分析
        ui_manager.show_loading_animation("Starting Security Analysis", 1.0)
        success = await cli.run_analysis(args)

        # 退出
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n⚠️  用户中断操作")
        sys.exit(1)

    except Exception as e:
        logger.error(f"程序执行错误: {e}")
        sys.exit(1)

    finally:
        await cli.cleanup()


if __name__ == '__main__':
    # 加载环境变量
    from dotenv import load_dotenv
    load_dotenv()

    # 运行主程序
    asyncio.run(main())