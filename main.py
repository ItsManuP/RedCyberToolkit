# main.py
import argparse
import sys
import logging  # moved import up for clarity
from core.log_config import setup_logging, get_logger
from core.orchestrator import Orchestrator
from core.ai_orchestrator import AIOrchestrator
from core.report_generator import ReportGenerator

logger = get_logger("main")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="RedCyberToolkit - Automated Red Teaming Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com --ip 192.168.1.10
  python main.py --target 192.168.1.10 --ip 192.168.1.10 --ai --output report.md --yes
  python main.py --target 192.168.1.10 --yes   (--ip is automatically set to the same value)
        """
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target hostname or description (e.g., example.com)"
    )
    parser.add_argument(
        "--ip",
        help="Target IP address (if not provided, the --target value is used)"
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Use AI Orchestrator (enables AI analysis with rate limiting)"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save report to file (if not specified, report is printed to stdout)"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging level (default: INFO)"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip confirmation prompt (non‑interactive mode)"
    )
    return parser.parse_args()

def main():
    args = parse_arguments()

    # If --ip was not given, use --target as the IP address
    target_ip = args.ip if args.ip else args.target

    # Setup logging with the specified level
    numeric_level = getattr(logging, args.log_level.upper(), logging.INFO)
    setup_logging(level=numeric_level)

    logger.info(f"RedCyberToolkit starting")
    logger.info(f"Target: {args.target} ({target_ip})")
    logger.info(f"AI mode: {'enabled' if args.ai else 'disabled'}")
    logger.info(f"Non‑interactive (--yes): {args.yes}")

    # Confirmation prompt (unless --yes is given)
    if not args.yes:
        print(f"\n⚠️  You are about to test {args.target} ({target_ip})")
        response = input("Do you want to continue? (y/N): ").strip().lower()
        if response not in ('y', 'yes'):
            print("Aborted by user.")
            return 0

    # Initialize the appropriate orchestrator
    try:
        if args.ai:
            logger.info("Using AI Orchestrator (with 7s rate limiting between API calls)")
            orchestrator = AIOrchestrator(target=args.target, ip=target_ip)
        else:
            logger.info("Using standard Orchestrator")
            orchestrator = Orchestrator(target=args.target, ip=target_ip)

        # Run the test
        final_state = orchestrator.run()

        # Generate report
        report_gen = ReportGenerator(final_state)
        report_content = report_gen.generate()

        # Output report
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report_content)
            logger.info(f"Report saved to {args.output}")
        else:
            print("\n" + "="*80)
            print("FINAL REPORT")
            print("="*80)
            print(report_content)

        logger.info("RedCyberToolkit finished successfully")
        return 0

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())