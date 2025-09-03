import argparse
import configparser
from network_monitor import NetworkMonitor

def main():
    # Main entry point for the AI-IDS app
    config = configparser.ConfigParser()
    config.read('config.ini')

    parser = argparse.ArgumentParser(description='AI-Powered Intrusion Detection System')
    parser.add_argument(
        'mode',
        choices=['train', 'monitor'],
        help='Run in "train" mode to capture packets and create a model, or "monitor" mode to perform real-time detection.'
    )
    parser.add_argument(
        '--interface',
        type=str,
        default=config.get('DEFAULT', 'DefaultInterface'),
        help='Network interface to use'
    )
    parser.add_argument(
        '--count',
        type=int,
        default=config.getint('DEFAULT', 'DefaultPacketCount'),
        help='Number of packets to capture in training mode'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='model.joblib',
        help='Path to save or load the model file'
    )

    args = parser.parse_args()

    try:
        monitor = NetworkMonitor(config)
        if args.mode == 'train':
            monitor.capture_and_train(args.interface, args.count, args.model)
        elif args.mode == 'monitor':
            monitor.start_monitoring(args.interface, args.model)
    except (ValueError, FileNotFoundError, PermissionError) as e:
        print(f'[!] ERROR: {e}')
        print('[!] Please run with sudo for packet capture permissions')
    except Exception as e:
        print(f'[!] An unexpected error occurred: {e}')


if __name__ == '__main__':
    main()