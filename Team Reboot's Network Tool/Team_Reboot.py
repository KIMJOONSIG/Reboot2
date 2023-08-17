import os
import sys
import pyfiglet

def feature1():
    print("Feature 1: Executing protocol_over.py")
    os.system('sudo python3 protocol_over.py')

def feature2():
    # 두 번째 기능의 코드를 여기에 작성하세요
    print("Feature 2 executed")

def feature3():
    # 세 번째 기능의 코드를 여기에 작성하세요
    print("Feature 3 executed")

def main():
    while True:
        reboot_ascii = pyfiglet.figlet_format("Team Reboot", font="slant")
        print(reboot_ascii)
        print("Copyright © Team Reboot")
        print("\n")
        print("1. protocol_over.py")
        print("2. Execute Feature 2")
        print("3. Execute Feature 3")
        print("4. Exit")
        choice = input("Enter the number of the feature you want to execute: ")

        if choice == '1':
            feature1()
        elif choice == '2':
            feature2()
        elif choice == '3':
            feature3()
        elif choice == '4':
            print("Exiting the program...")
            sys.exit()
        else:
            print("Invalid choice. Please enter a valid number.")

if __name__ == "__main__":
    main()
