import pandas as pd 
import os
from collections import Counter
import numpy as np
import string

def check_name(vals):
	# Deletes all names from given dataframe
	# where Names in headers are hexadecimal numbers
    # because names were of kind [".txt", ".*", "0x4000" ...]

	newlist = []
	try:
		vals = vals[1:-1]
	except TypeError as e:
		print(f"TypeError at value {vals}")
		return None
	vals = vals[1:-1]
	vals = "".join(vals.split("'"))
	vals = vals.split(", ")
	for val in vals:
		if val[0] == ".":
			newlist.append(val)

	return newlist

#Function call to replace name column
# df = pd.read_csv("Static_Analysis_Data-Malware-EngineeredFeatures.csv")
# df["Name:"] = df["Name:"].apply(check_name)
# df.to_csv("Static_Analysis_Data-Malware-EngineeredFeatures2.csv")

def check_if_day_or_month(str):
	# Checks if a string is a day or a month
    # because many common words from string.txt  
    # files were days or months
	months = ['January', 'February', 'March', 'April', 'May', 'June', 'July','August', 'September', 'October', 'November', 'December']
	days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

	if str in months or str in days:
		return False

	return True

def useful_words(path):
	# Returns a list of all words which can be
    # identified as keywords in the string.txt
    # file. This was done because many words
    # were showing a pattern of being repeated in
    # benign and malware files.

	words = []

	try:
		file1 = open(path)
		fcontent = file1.readlines()
	except (UnicodeDecodeError, OSError):
		return None

	for i, line in enumerate(fcontent):
		line = line.split()

		# First condition to make sure only one word in line.
		# 2nd and 3rd condition to get rid of all lines where
		# there are useless characters.
		# 4th condition to get actual words because without it
		# common words were occuring like 'kkkk' and 'YYUa'.
		# Final condition because Sunday monday were occuring in common words.
		if len(line) == 1 and line[0][0].isupper() and line[0].isalpha() and len(set(line[0])) > 5 and check_if_day_or_month(line[0]):
			words.append(line[0])

	return words

def most_common_words(label="Malware"):
    # Returns a list of 50 most commonly occuring words
    # in malware or benign folder according to the label
    # argument. Once this list has been received, we create
    # a feature vector where "1" indicates presence of that
    # keyword and "0" indicates absence.
	words = []
	if label == "Malware":
		dirlist = os.listdir('./Static_Analysis_Data/Malware/')
		# Loop over filenames 
		for folder in dirlist:
			# Loop over malware interior folders
			dirlist2 = os.listdir('./Static_Analysis_Data/Malware/' + str(folder))
			for i, sha in enumerate(dirlist2):
				path = 'Static_Analysis_Data/Malware/'+ folder + '/' + sha + '/String.txt'
				if useful_words(path) is None:
					print("UnicodeDecodeError")
				else:
					words = words + useful_words(path)

				if i%100 == 0:
					print(f"{i} files processed.")

	elif label == "Benign":
		dirlist = os.listdir('./Static_Analysis_Data/Benign/')
		# Loop over filenames 
		for i, sha in enumerate(dirlist):
			path = 'Static_Analysis_Data/Benign/' + sha + '/String.txt'
			if useful_words(path) is None:
				print("UnicodeDecodeError")
			else:
				words = words + useful_words(path)

			if i%100 == 0:
				print(f"{i} files processed.")

	counter = Counter(words)
	most_occur = counter.most_common(50) 
	  
	return most_occur
			
def create_common_words_data(common_words, label = "Malware"):
	all_data =[]
	if label == "Benign":

		dirlist = os.listdir('./Static_Analysis_Data/Benign/')
		# Loop over filenames 
		# dirlist = dirlist[:4]

		for i, sha in enumerate(dirlist):
			data = dict(zip(common_words, np.zeros(len(common_words))))

			path = 'Static_Analysis_Data/Benign/' + sha + '/String.txt'
			if useful_words(path) is None:
				print("UnicodeDecodeError")
			else:
				for word in useful_words(path):
					if word in common_words:
						data[word] = 1

			data["name"] = sha
			all_data.append(data)

			if i%100 == 0:
				print(f"{i} files processed.")

		return all_data

	elif label == "Malware":
		dirlist = os.listdir('./Static_Analysis_Data/Malware/')
		# Loop over filenames 
		for folder in dirlist:
			# Loop over malware interior folders
			dirlist2 = os.listdir('./Static_Analysis_Data/Malware/' + str(folder))
			for i, sha in enumerate(dirlist2):
				data = dict(zip(common_words, np.zeros(len(common_words))))

				path = 'Static_Analysis_Data/Malware/'+ folder + '/' + sha + '/String.txt'
				if useful_words(path) is None:
					print("UnicodeDecodeError")
				else:
					for word in useful_words(path):
						if word in common_words:
							data[word] = 1

				data["name"] = sha
				all_data.append(data)

				if i%100 == 0:
					print(f"{i} files processed in {folder} folder.")

		return all_data

# print("Finding most common words in Benign folder")
# most_occur = most_common_words("Benign")
# df = pd.DataFrame(dict(most_occur), index=[0])
# print("Writing to DataFrame")
# df.to_csv("MostCommonWords-Benign.csv")

# print("Finding most common words in Malware folder")
# most_occur = most_common_words("Malware")
# df = pd.DataFrame(dict(most_occur), index = [0])
# print("Writing to DataFrame")
# df.to_csv("MostCommonWords-Malware.csv")

# df = pd.read_csv("MostCommonWords-Benign.csv")
# df.drop("Unnamed: 0", inplace=True, axis=1)
# common_words_benign = list(df.columns)

# df = pd.read_csv("MostCommonWords-Malware.csv")
# df.drop("Unnamed: 0", inplace=True, axis=1)
# common_words_malware = list(df.columns)

# common_words = common_words_malware + common_words_benign

# print("Creating feature vector in Benign folder")
# datab = create_common_words_data(label="Benign", common_words=common_words)
# dfb = pd.DataFrame(datab)
# dfb.to_csv("CommonWords-Benign.csv")

# print("Creating feature vector in Malware folder")
# datam = create_common_words_data(common_words=common_words)
# dfm = pd.DataFrame(datam)
# dfm.to_csv("CommonWords-Malware.csv")

def parse_single_example(path, raw_features, data):
	# Takes a single filepath and returns a dictionary of raw feature and values. 
	# No derived feature logic here.
	try:
		file1 = open(path)
		fcontent = file1.readlines()
	except UnicodeDecodeError as e:
		return None
	

	for line in fcontent:
		line = line.split()
		for feat in raw_features:
			if feat in line:
				data[feat] = line[-1]
				break

	return data

def parse_eng_example(path, raw_features, data):
	# Takes a single filepath and returns a dictionary of raw feature and values. 
	# No derived feature logic here.
	try:
		file1 = open(path)
		fcontent = file1.readlines()
	except UnicodeDecodeError as e:
		return None
	

	for line in fcontent:
		line = line.split()
		for feat in raw_features:
			if feat in line:
				if feat not in data:
					data[feat] = []

                # engineered_features[0] is Name in this case
                # so this if condition checks whether the name is valid or not
                # i.e. whether it is hexadecimal or not.

				if feat == engineered_features[0] and all(c in string.hexdigits for c in line[-1]):
					break
				else:
					data[feat].append(line[-1])
                break

	return data

def proc_raw_features(raw_features):
	# Make raw features usable
	raw_features = ": ".join(raw_features.split(','))
	raw_features = raw_features.split()
	return raw_features

raw_features = "e_cblp, e_cp, e_cparhdr, e_maxalloc, e_sp, e_lfanew, NumberOfSections, MajorLinkerVersion, MinorLinkerVersion, SizeOfCode,SizeOfInitializedData, SizeOfUninitializedData,AddressOfEntryPoint, BaseOfCode, BaseOfData,MajorOperatingSystemVersion, MinorOperatingSystemVersion,MajorImageVersion, MinorImageVersion, CheckSum,MajorSubsystemVersion, MinorSubsystemVersion,Subsystem,SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve,SizeOfHeapCommit, LoaderFlags"

# Preprocess raw_features
raw_features = proc_raw_features(raw_features)

def create_data(label="Malware"):
    if label == "Benign":

        dirlist = os.listdir('./Static_Analysis_Data/Benign/')

        all_data = []
        # Loop over filenames 
        for i, sha in enumerate(dirlist):
            path = 'Static_Analysis_Data/Benign/' + sha + '/Structure_Info.txt'
            data = {}
            data = parse_single_example(path, raw_features, data)

            if data is None:
                print("Error in encoding for file " + str(sha))
            else:
                data["name"] = sha
                all_data.append(data)

            if i%100 == 0:
                print(f"{i} files processed.")

        return all_data

    elif label == "Malware":
        dirlist = os.listdir('./Static_Analysis_Data/Malware/')

        all_data = []
        # Loop over filenames 
        for folder in dirlist:
            # Loop over malware interior folders
            dirlist2 = os.listdir('./Static_Analysis_Data/Malware/' + str(folder))

            for i, sha in enumerate(dirlist2):
                path = 'Static_Analysis_Data/Malware/'+ folder + '/' + sha + '/Structure_Info.txt'
                data = {}
                data = parse_single_example(path, raw_features, data)

                if data is None:
                    print("Error in encoding for file " + str(sha))
                else:
                    data["name"] = sha
                    all_data.append(data)

                if i%100 == 0:
                    print(f"{i} files processed in {folder} folder.")

        return all_data

def get_entropy(path):
	# Reads all entropy values from struct_info.txt
    # and returns the average entropy value for the
    # file specified in path arguement.	
	try:
		file1 = open(path)
		fcontent = file1.readlines()
	except UnicodeDecodeError as e:
		return None

	entropies = []
	for line in fcontent:
		line = line.split()
		if "Entropy:" in line:
			entropies.append(float(line[1]))

	if len(entropies) == 0:
		return -1
	else:		
		entropy = sum(entropies)/len(entropies)
		return entropy

engineered_features = "Name, ImageBase, FileSize, FileInfo, SectionAlignment, FileAlignment, SizeOfImage"
engineered_features = proc_raw_features(engineered_features)

def get_engineered_features(label="Malware"):
    if label == "Benign":
        dirlist = os.listdir('./Static_Analysis_Data/Benign/')

        all_data = []
        # Loop over filenames 
        for i, sha in enumerate(dirlist):
            path = 'Static_Analysis_Data/Benign/' + sha + '/Structure_Info.txt'
            
            data = {}
            data = parse_eng_example(path, engineered_features, data) 
            entropy = get_entropy(path)
            if data is None and entropy is None:
                print("Error in encoding for file " + sha)
            else:
                data["name"] = sha
                data["Entropy:"] = entropy
                all_data.append(data)

            if i%100 == 0:
                print(f"{i} files processed.")

        return all_data


    elif label == "Malware":
        dirlist = os.listdir('./Static_Analysis_Data/Malware/')

        all_data = []
        # Loop over filenames 
        for folder in dirlist:
            # Loop over malware interior folders
            dirlist2 = os.listdir('./Static_Analysis_Data/Malware/' + str(folder))

            for i, sha in enumerate(dirlist2):
                path = 'Static_Analysis_Data/Malware/'+ folder + '/' + sha + '/Structure_Info.txt'
                data = {}
                
                # Find all engineered features in malware
                data = parse_eng_example(path, engineered_features, data)
                entropy = get_entropy(path)

                if data is None and entropy is None:
                    print("Error in encoding for file " + sha)
                else:
                    data["name"] = sha
                    data["Entropy:"] = entropy
                    all_data.append(data)

                if i%100 == 0:
                    print(f"{i} files processed in {folder} folder.")

        return all_data	

# data = get_engineered_features()
# df = pd.DataFrame(data)
# df.to_csv("Static_Analysis_Data-Benign-EngineeredFeatures.csv")

# datam = get_engineered_features_malware()
# dfm = pd.DataFrame(datam)
# dfm.to_csv("Static_Analysis_Data-Malware-EngineeredFeatures.csv")

# data = create_csv_malware()
# df = pd.DataFrame(data)
# df.to_csv("Static_Analysis_Data-Malware.csv")


