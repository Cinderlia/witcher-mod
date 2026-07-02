import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from if_branch_coverage import check_if_branch_coverage


def main():
    result = check_if_branch_coverage(6)
    print(result)


if __name__ == "__main__":
    main()
