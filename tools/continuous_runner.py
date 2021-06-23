import os
import glog
import argparse
import time


def main():
    argument_parser = argparse.ArgumentParser(
        description='Parse output of FlashRoute.')
    argument_parser.add_argument("-o", type=str, required=True,
                                 help='Directory of output.')
    argument_parser.add_argument("-e", type=str, required=True,
                                 help='Path to Flashroute.')
    argument_parser.add_argument("-n", type=int, required=True,
                                 help='Number of executions.')
    argument_parser.add_argument("-d", type=int, required=True,
                                 help='Interval in second between two continuous executions.')
    argument_parser.add_argument("-l", type=str, required=True,
                                 help='Label of outputs.')
    argument_parser.add_argument("-a", type=str, required=True,
                                 help='Arguments for Flashroute.')
    args = argument_parser.parse_args()

    output_dir = os.path.abspath(args.o)

    if not os.path.isdir(output_dir):
        glog.info(f"{output_dir} is not a directory.")
        return

    previous_output = ""
    read_history_arg = ""
    for i in range(0, args.n):
        glog.info(f"{i} round")
        output_filename = os.path.join(output_dir, f"{args.l}_{i}")
        if previous_output != "":
            read_history_arg = f" --history_probing_result {previous_output}"

        command = f"{args.e} -- --output {output_filename}{read_history_arg} {args.a}"
        glog.info(command)
        os.system(command)
        previous_output = output_filename
        time.sleep(args.d)


if __name__ == "__main__":
    main()
