import json
import sys

def analyze(log_file):
    #with open(log_file, "r") as logs:
    #    lines = logs.readlines()
        # for line in lines:
        #     print(line)
        #     input("paus")
    contents = json.loads(log_file.read())
    
    print(contents)

if __name__=="__main__":
    analyze(sys.argv[1])