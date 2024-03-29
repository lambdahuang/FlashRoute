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
    argument_parser.add_argument("-n", type=int, required=False, default=0,
                                 help='Number of executions.')
    argument_parser.add_argument("-t", type=int, required=False,
                                 help='Time to run (minutes)')
    argument_parser.add_argument("-d", type=int, required=True,
                                 help='Interval in second between two continuous executions.')
    argument_parser.add_argument("-l", type=str, required=True,
                                 help='Label of outputs.')
    argument_parser.add_argument("-a", type=str, required=True,
                                 help='Arguments for Flashroute.')
    argument_parser.add_argument("-nohistory", type=bool, required=False, default=False,
                                 help='Not reuse history.')
    argument_parser.add_argument("-ss", type=int, required=False, default=0,
                                 help='Probing initial speed.')
    argument_parser.add_argument("-si", type=int, required=False, default=0,
                                 help='Probing speed step.')
    argument_parser.add_argument("-ps", type=int, required=False, default=0,
                                 help='Initial prefix length.')
    argument_parser.add_argument("-test", type=bool, required=False, default=False,
                                 help='Test mode.')
    args = argument_parser.parse_args()

    output_dir = os.path.abspath(args.o)

    if not os.path.isdir(output_dir):
        glog.info(f"{output_dir} is not a directory.")
        return

    previous_output = ""
    read_history_arg = ""
    # stair speed probing
    start_speed = args.ss
    speed_step = args.si
    speed_arg = ""
    speed_label = ""

    # stair prefix
    start_prefix = args.ps
    prefix_arg = ""

    i = 0
    start = time.time()
    while (args.n != 0 and i < args.n) or ((time.time() - start) / 60 <= args.t):
        glog.info(f"{i} round")
        if args.nohistory == False and previous_output != "":
            read_history_arg = f" --history_probing_result {previous_output}"
        
        if start_speed != 0 and speed_step !=0:
            speed_arg = f" --probing_rate {start_speed} "
            speed_label = f"probibng_rate_{start_speed}"
            output_filename = os.path.join(output_dir, f"{args.l}_{speed_label}")
            start_speed += speed_step
        elif start_prefix != 0:
            prefix_arg = f" --granularity {start_prefix} "
            prefix_label = f"granularity_{start_prefix}"
            output_filename = os.path.join(output_dir, f"{args.l}_{prefix_label}")
            start_prefix += 1
        else:
            # generate output filename
            output_filename = os.path.join(output_dir, f"{args.l}_{i}")

        command = f"{args.e} --output {output_filename} {read_history_arg} {speed_arg} {prefix_arg} {args.a}"
        glog.info(command)
        if not args.test:
            os.system(command)
            time.sleep(args.d)
        previous_output = output_filename
        i += 1


if __name__ == "__main__":
    main()
