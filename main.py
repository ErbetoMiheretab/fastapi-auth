

def power_sum(nums, index):
    if index == len(nums):
        return 0

    if nums[index] <= 0:
        return (nums[index] ** 4) + power_sum(nums, index + 1)

    return power_sum(nums, index + 1)


def process_cases(case, total):
    if case == total:
        return []

    x = int(input())
    nums = list(map(int, input().split()))

    if len(nums) != x:
        result = -1
    else:
        result = power_sum(nums, 0)

    # Accumulate results in a list recursively instead of printing directly
    return [result] + process_cases(case + 1, total)


def main():
    t = int(input())
    results = process_cases(0, t)

    # Print ALL results at once after all inputs are read
    print("\n".join(map(str, results)))


if __name__ == "__main__":
    main()