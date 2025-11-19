#!/usr/bin/env python3
"""
Dynamic Analyzer CLI - Command-line interface for dynamic analysis
"""
import argparse
import logging
import sys
import os
import yaml
from pathlib import Path

# Add the current directory to the path to allow imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.orchestrator import DynamicAnalysisOrchestrator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file"""
    if config_path is None:
        config_path = Path(__file__).parent / "config" / "analysis_config.yaml"
    
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def analyze_command(args):
    """Run dynamic analysis on an APK"""
    logger.info("Starting dynamic analysis...")
    
    # Load configuration
    config = load_config(args.config)
    
    # Create orchestrator
    orchestrator = DynamicAnalysisOrchestrator(
        avd_name=args.avd or config['emulator']['avd_name'],
        output_dir=args.output or config['output']['base_dir'],
        android_sdk_root=config['sdk'].get('android_sdk_root'),
        adb_path=config['sdk'].get('adb_path', 'adb'),
        emulator_path=config['sdk'].get('emulator_path', 'emulator'),
        frida_server_path=args.frida_server or config['frida'].get('server_path')
    )
    
    # Run analysis (Phase 2.5 - Hybrid HTTPS capture)
    results = orchestrator.analyze_apk(
        apk_path=args.apk,
        analysis_duration=args.duration or config['analysis']['default_duration'],
        spawn_mode=args.spawn if args.spawn is not None else config['analysis']['spawn_mode'],
        create_snapshot=args.snapshot if args.snapshot is not None else config['analysis']['create_snapshots'],
        # Phase 2 parameters
        enable_ui_automation=args.enable_ui_automation if hasattr(args, 'enable_ui_automation') and args.enable_ui_automation is not None else config['analysis'].get('enable_ui_automation', True),
        enable_logcat=args.enable_logcat if hasattr(args, 'enable_logcat') and args.enable_logcat is not None else config['analysis'].get('enable_logcat', True),
        ui_exploration_duration=args.ui_duration or config['analysis'].get('ui_exploration_duration', 180),
        # Phase 2.5: HTTPS Interception parameters
        enable_mitm=args.mitm_proxy if hasattr(args, 'mitm_proxy') else False,
        proxy_host=args.proxy_host if hasattr(args, 'proxy_host') else '127.0.0.1',
        proxy_port=args.proxy_port if hasattr(args, 'proxy_port') else 8080
    )
    
    # Print results
    if results['success']:
        logger.info("\n" + "="*60)
        phase_label = "Phase 2.5" if 'https_statistics' in results else "Phase 2-Light"
        logger.info(f"Analysis Results Summary ({phase_label}):")
        logger.info("="*60)
        logger.info(f"Package: {results.get('package_name', 'N/A')}")
        logger.info(f"Total API calls: {results['statistics']['total_calls']}")
        logger.info(f"Duration: {results['statistics']['duration_seconds']:.1f} seconds")
        
        # Phase 2: UI Exploration results
        if 'ui_exploration' in results:
            logger.info(f"\nUI Exploration (Phase 2):")
            logger.info(f"  Actions taken: {results['ui_exploration']['total_actions']}")
            logger.info(f"  Activities explored: {results['ui_exploration']['activities_explored']}")
            logger.info(f"  Elements clicked: {results['ui_exploration']['elements_clicked']}")
            logger.info(f"  Screenshots: {results['ui_exploration']['screenshots']}")
        
        # Phase 2: Logcat results
        if 'logcat_findings' in results:
            logger.info(f"\nSystem Monitoring (Phase 2):")
            logger.info(f"  Permissions detected: {results['logcat_findings']['summary']['permissions_requested']}")
            logger.info(f"  Intents broadcasted: {results['logcat_findings']['summary']['intents_broadcasted']}")
            logger.info(f"  Services started: {results['logcat_findings']['summary']['services_started']}")
            if results['logcat_findings']['summary']['camera_accesses'] > 0:
                logger.info(f"  📷 Camera accesses: {results['logcat_findings']['summary']['camera_accesses']}")
            if results['logcat_findings']['summary']['microphone_accesses'] > 0:
                logger.info(f"  🎤 Microphone accesses: {results['logcat_findings']['summary']['microphone_accesses']}")
        
        # Phase 2.5: HTTPS Interception results
        if 'https_statistics' in results:
            https_stats = results['https_statistics']
            logger.info(f"\n🔒 HTTPS Traffic Interception (Phase 2.5):")
            logger.info(f"  Requests captured: {https_stats['total_requests']}")
            logger.info(f"  Responses captured: {https_stats['total_responses']}")
            logger.info(f"  Unique domains: {https_stats['unique_domains']}")
            
            # Show sensitive data findings
            if results.get('https_sensitive_data'):
                sensitive_data = results['https_sensitive_data']
                # Count total findings across all categories
                total_findings = sum(len(findings) for findings in sensitive_data.values())
                
                if total_findings > 0:
                    logger.info(f"  ⚠️  Sensitive data detected: {total_findings} finding(s)")
                    
                    # Show breakdown by category
                    for category, findings in sensitive_data.items():
                        if findings:
                            logger.info(f"    - {category}: {len(findings)}")
        
        logger.info(f"\nAPI calls by category:")
        for category, count in results['statistics']['by_category'].items():
            if count > 0:
                logger.info(f"  {category}: {count}")
        
        logger.info(f"\nOutput files:")
        logger.info(f"  API calls: {results['api_calls_file']}")
        logger.info(f"  Network: {results['network_file']}")
        if 'https_traffic_file' in results:
            logger.info(f"  🔒 HTTPS traffic: {results['https_traffic_file']}")
        if 'ui_exploration' in results:
            logger.info(f"  UI exploration: {results['output_dir']}/ui_exploration.json")
        if 'logcat_findings' in results:
            logger.info(f"  Logcat analysis: {results['output_dir']}/logcat_analysis.json")
        logger.info(f"  Directory: {results['output_dir']}")
        
        return 0
    else:
        logger.error(f"Analysis failed: {results.get('error', 'Unknown error')}")
        return 1


def list_avds_command(args):
    """List available Android Virtual Devices"""
    config = load_config(args.config)
    
    orchestrator = DynamicAnalysisOrchestrator(
        avd_name="dummy",
        output_dir="/tmp",
        adb_path=config['sdk'].get('adb_path', 'adb'),
        emulator_path=config['sdk'].get('emulator_path', 'emulator')
    )
    
    avds = orchestrator.list_available_avds()
    
    if avds:
        logger.info("Available AVDs:")
        for avd in avds:
            logger.info(f"  - {avd}")
    else:
        logger.warning("No AVDs found. Create one with: avdmanager create avd")
    
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Matrisks Dynamic Analyzer - Android malware dynamic analysis tool'
    )
    
    parser.add_argument('--config', '-c',
                       help='Path to configuration file',
                       default=None)
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze an APK file')
    analyze_parser.add_argument('apk', help='Path to APK file')
    analyze_parser.add_argument('--avd', help='AVD name to use')
    analyze_parser.add_argument('--duration', '-d', type=int,
                               help='Analysis duration in seconds')
    analyze_parser.add_argument('--output', '-o',
                               help='Output directory')
    analyze_parser.add_argument('--spawn', action='store_true', default=None,
                               help='Spawn app with Frida (default)')
    analyze_parser.add_argument('--attach', dest='spawn', action='store_false',
                               help='Attach to running app')
    analyze_parser.add_argument('--snapshot', action='store_true', default=None,
                               help='Create snapshot before analysis')
    analyze_parser.add_argument('--no-snapshot', dest='snapshot', action='store_false',
                               help='Skip snapshot creation')
    analyze_parser.add_argument('--frida-server',
                               help='Path to frida-server binary')
    # Phase 2-Light arguments
    analyze_parser.add_argument('--enable-ui-automation', action='store_true', default=None,
                               help='Enable UI automation (Phase 2, default: enabled)')
    analyze_parser.add_argument('--disable-ui-automation', dest='enable_ui_automation', action='store_false',
                               help='Disable UI automation (use passive monitoring)')
    analyze_parser.add_argument('--enable-logcat', action='store_true', default=None,
                               help='Enable logcat monitoring (Phase 2, default: enabled)')
    analyze_parser.add_argument('--disable-logcat', dest='enable_logcat', action='store_false',
                               help='Disable logcat monitoring')
    analyze_parser.add_argument('--ui-duration', type=int,
                               help='UI exploration duration in seconds (default: 180)')
    analyze_parser.add_argument('--fast', action='store_true',
                               help='Fast mode: use saved snapshot if available (skip emulator boot)')
    # Phase 2.5: HTTPS Interception options
    analyze_parser.add_argument('--mitm-proxy', action='store_true',
                               help='Enable MITM proxy mode for Cronet/gRPC apps (activates SSL unpinning)')
    analyze_parser.add_argument('--proxy-host', default='127.0.0.1',
                               help='Proxy host address (default: 127.0.0.1)')
    analyze_parser.add_argument('--proxy-port', type=int, default=8080,
                               help='Proxy port (default: 8080)')
    analyze_parser.set_defaults(func=analyze_command)
    
    # List AVDs command
    list_parser = subparsers.add_parser('list-avds', help='List available AVDs')
    list_parser.set_defaults(func=list_avds_command)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Run command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
