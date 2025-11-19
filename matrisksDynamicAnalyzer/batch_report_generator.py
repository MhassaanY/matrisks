#!/usr/bin/env python3
"""
Batch Report Generator for Dynamic Analysis
Generates comprehensive reports for one or multiple analysis directories
"""

import os
import sys
import argparse
from pathlib import Path
from report_generator import DynamicReportGenerator


def generate_report_for_directory(analysis_dir: str, verbose: bool = True):
    """Generate reports for a single analysis directory"""
    try:
        if verbose:
            print(f"\n{'='*70}")
            print(f"Processing: {os.path.basename(analysis_dir)}")
            print(f"{'='*70}")
        
        generator = DynamicReportGenerator(analysis_dir)
        report_paths = generator.save_all_reports()
        
        if verbose:
            print(f"\n✅ Reports generated successfully!")
            print(f"   - JSON:  {os.path.basename(report_paths['json'])}")
            print(f"   - CSV:   {os.path.basename(report_paths['csv'])}")
            print(f"   - HTML:  {os.path.basename(report_paths['html'])}")
        
        return True, report_paths
        
    except Exception as e:
        print(f"❌ Error generating reports for {analysis_dir}: {e}")
        return False, None


def find_analysis_directories(root_dir: str = "scanned_results"):
    """Find all analysis directories in the results folder"""
    analysis_dirs = []
    
    if not os.path.exists(root_dir):
        print(f"Error: Directory not found: {root_dir}")
        return analysis_dirs
    
    for item in os.listdir(root_dir):
        item_path = os.path.join(root_dir, item)
        if os.path.isdir(item_path) and item.startswith('analysis_'):
            analysis_dirs.append(item_path)
    
    return sorted(analysis_dirs)


def main():
    parser = argparse.ArgumentParser(
        description="Generate comprehensive reports for dynamic analysis results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report for specific analysis
  python batch_report_generator.py -d scanned_results/analysis_MyApp_20231115_120000
  
  # Generate reports for all analyses
  python batch_report_generator.py --all
  
  # Generate reports for last N analyses
  python batch_report_generator.py --last 5
  
  # Generate reports for analyses matching pattern
  python batch_report_generator.py --pattern "traffic-racer"
        """
    )
    
    parser.add_argument(
        '-d', '--directory',
        help='Specific analysis directory to process',
        type=str
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Generate reports for all analysis directories'
    )
    
    parser.add_argument(
        '--last',
        type=int,
        metavar='N',
        help='Generate reports for last N analyses'
    )
    
    parser.add_argument(
        '--pattern',
        type=str,
        help='Generate reports for analyses matching this pattern'
    )
    
    parser.add_argument(
        '--root',
        type=str,
        default='scanned_results',
        help='Root directory containing analysis results (default: scanned_results)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - minimal output'
    )
    
    args = parser.parse_args()
    
    # Determine which analyses to process
    analyses_to_process = []
    
    if args.directory:
        # Single specific directory
        if os.path.exists(args.directory):
            analyses_to_process = [args.directory]
        else:
            print(f"Error: Directory not found: {args.directory}")
            return 1
    
    elif args.all or args.last or args.pattern:
        # Find all analysis directories
        all_analyses = find_analysis_directories(args.root)
        
        if not all_analyses:
            print(f"No analysis directories found in {args.root}")
            return 1
        
        if args.all:
            analyses_to_process = all_analyses
        
        elif args.last:
            analyses_to_process = all_analyses[-args.last:]
        
        elif args.pattern:
            analyses_to_process = [
                d for d in all_analyses 
                if args.pattern.lower() in os.path.basename(d).lower()
            ]
            
            if not analyses_to_process:
                print(f"No analyses found matching pattern: {args.pattern}")
                return 1
    
    else:
        # No arguments provided - show help
        parser.print_help()
        return 1
    
    # Process all selected analyses
    verbose = not args.quiet
    
    if verbose:
        print(f"\n📊 Batch Report Generator")
        print(f"Processing {len(analyses_to_process)} analysis director{'ies' if len(analyses_to_process) != 1 else 'y'}")
        print(f"{'='*70}\n")
    
    successful = 0
    failed = 0
    
    for analysis_dir in analyses_to_process:
        success, _ = generate_report_for_directory(analysis_dir, verbose=verbose)
        if success:
            successful += 1
        else:
            failed += 1
    
    # Summary
    if verbose:
        print(f"\n{'='*70}")
        print(f"📈 Summary:")
        print(f"   Total processed: {len(analyses_to_process)}")
        print(f"   ✅ Successful:   {successful}")
        if failed > 0:
            print(f"   ❌ Failed:       {failed}")
        print(f"{'='*70}\n")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
