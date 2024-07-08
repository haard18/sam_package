import argparse
import os
from sam.analyzer import analyze_return, analyze_overflow_and_return, analyze_underflow_and_return, analyze_reentrancy, check_private_key_exposure, analyze_floating_pragma, analyze_denial_of_service, analyze_unchecked_external_calls, analyze_greedy_suicidal_functions, print_vulnerabilities, save_report

def analyze_file(file_path):
    with open(file_path, 'r') as file:
        code = file.read()

    analyze_return(code)
    analyze_overflow_and_return(code)
    analyze_underflow_and_return(code)
    analyze_reentrancy(code)
    check_private_key_exposure(code)
    analyze_floating_pragma(code)
    analyze_denial_of_service(code)
    analyze_unchecked_external_calls(code)
    analyze_greedy_suicidal_functions(code)

    print_vulnerabilities()

    report_file_path = "report.json"
    save_report(report_file_path)
    print(f"\nVulnerability report saved to {report_file_path}\n")

def main():
    parser = argparse.ArgumentParser(description="SAM - Smart Contract Vulnerability Analyzer")
    parser.add_argument("file_or_directory", metavar="file_or_directory", type=str, nargs="?", default=".", help="File or directory to analyze (default: current directory)")
    parser.add_argument("--check", metavar="check_name", type=str, help="Run a specific vulnerability check")
    
    args = parser.parse_args()

    if os.path.isfile(args.file_or_directory):
        analyze_file(args.file_or_directory)
    elif os.path.isdir(args.file_or_directory):
        for root, dirs, files in os.walk(args.file_or_directory):
            for file in files:
                if file.endswith(".lua"):
                    file_path = os.path.join(root, file)
                    analyze_file(file_path)
    else:
        print(f"Error: {args.file_or_directory} is not a valid file or directory.")

if __name__ == "__main__":
    main()
