from output_parser import FlashRouteParser
import glog
import argparse
import glog

if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(
        description='Parse output of FlashRoute.')
    argument_parser.add_argument("-f", type=str, required=True,
                                 help='Parse output of FlashRoute.')
    args = argument_parser.parse_args()
    flashroute_parser = FlashRouteParser(args.f)
    glog.info(f"Start to read data from {args.f}")
    i = 0
    while(True):
        result = flashroute_parser.next()
        i += 1
        if result is None:
            break
    
    glog.info(f"Finished. Read {i} records.")

