import argparse

my_args = argparse.Namespace(
    target="127.0.0.1",
    ports=["22", "80"],
    output_dir="./reports"
)

print(my_args.target)
print(my_args.ports)
