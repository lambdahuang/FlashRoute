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
    argument_parser.add_argument("-r", type=str, required=True,
                                 help='Path to Reprobe Target Generator.')
    argument_parser.add_argument("-n", type=int, required=False, default=0,
                                 help='Number of executions.')
    argument_parser.add_argument("-t", type=int, required=False,
                                 help='Time to run (minutes)')
    argument_parser.add_argument("-d", type=int, required=True,
                                 help='Interval in second between two continuous executions.')
    argument_parser.add_argument("-l", type=str, required=True,
                                 help='Label of outputs.')
    argument_parser.add_argument("-ma", type=str, required=True,
                                 help='Arguments for the main scan of Flashroute.')
    argument_parser.add_argument("-ea", type=str, required=True,
                                 help='Arguments for the extra scans of Flashroute.')
    argument_parser.add_argument("-test", type=bool, required=False, default=False,
                                 help='Test mode.')
    args = argument_parser.parse_args()

    output_dir = os.path.abspath(args.o)

    if not os.path.isdir(output_dir):
        glog.info(f"{output_dir} is not a directory.")
        return

    # scan label
    scan_label = args.l

    # scan arguments
    main_scan_argument = args.ma
    extra_scan_argument = args.ea

    reprobe_target_file = ""
    reprobe_nonstop_file = ""
    reprobe_target_generator_command = ""


    i = 0
    start = time.time()
    while (args.n != 0 and i < args.n) or ((time.time() - start) / 60 <= args.t):
        glog.info(f"{i} round")
        output_filename = os.path.join(output_dir, f"{scan_label}_{i}")
        reprobe_target_file_prefix = os.path.join(output_dir, f"{scan_label}_{i}_reprobe_target")

        command = ""
        if i == 0:
            command = f"{args.e} --output {output_filename} {main_scan_argument}"
            glog.info(command)
        else:
            reprobe_target_file = f"{reprobe_target_file_prefix}"
            reprobe_nonstop_file = f"{reprobe_target_file_prefix}_nonstop"
            command = f"{args.e} --output {output_filename} --noforward_probing --targets {reprobe_target_file} --nonstop_set_file {reprobe_nonstop_file} {extra_scan_argument}"
       
        if not args.test:
            os.system(command)
            time.sleep(args.d)

        # Run reprobe target generator
        reprobe_target_generator_command = f"{args.f} --directory {output_dir} --label {scan_label} --start 0 --end {i} --output {reprobe_target_file_prefix}"
        if not args.test:
            os.system(reprobe_target_generator_command)
            time.sleep(args.d)
        
        i += 1


if __name__ == "__main__":
    main()
