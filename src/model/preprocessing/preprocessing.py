from filtering import filtering
from scaling import scaling
from labeling import labeling

if __name__ == "__main__":
    print("Starting preprocessing...\n")
    #labeling()  # adds Label to raw CSVs
    output = filtering()  # merges labeled CSVs, returns path
    scaling(output)  # scales and encodes, saves final CSV
    print("\nFinished!")
