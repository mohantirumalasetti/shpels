import threading
import time
import sys
import features
import pickle
import warnings

def print_banner():
    banner = """
  \033[96m███████╗██╗  ██╗██████╗ ███████╗██╗     ███████╗
  ██╔════╝██║  ██║██╔══██╗██╔════╝██║     ██╔════╝
  ███████╗███████║██████╔╝█████╗  ██║     ███████╗
  ╚════██║██╔══██║██╔═══╝ ██╔══╝  ██║     ╚════██║
  ███████║██║  ██║██║     ███████╗███████╗███████║
  ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝\033[0m
  
           \033[92m- Malicious URL Detector -
    
       \033[95m-------------------------------------\033[0m
       | \033[93mDeveloped by: Mohantirumalasetti\033[0m  |
       | \033[93mVersion: 1.0\033[0m                      |
       \033[95m-------------------------------------\033[0m
  """
    print(banner)

def loading_animation():
    while not process_complete:
        sys.stdout.write('\r\033[1m\033[96mLoading...\033[0m |')
        time.sleep(0.1)
        sys.stdout.write('\r\033[1m\033[96mLoading...\033[0m /')
        time.sleep(0.1)
        sys.stdout.write('\r\033[1m\033[96mLoading...\033[0m -')
        time.sleep(0.1)
        sys.stdout.write('\r\033[1m\033[96mLoading...\033[0m \\')
        time.sleep(0.1)
        sys.stdout.flush()

def process(url):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        features_list = features.FeaturesExtractor(url)
        
        model = pickle.load(open("./model/model.pkl", "rb"))

        print("\n")
        input_data = [features_list.getfeatureslist()]
        predicted_labels = model.predict(input_data)
        if predicted_labels == -1:
            print("\033[1m\033[91mThis is Phishing Site\033[0m")
        elif predicted_labels == 1:
            print("\033[1mThis is Legitimate Site\033[0m")

        predicted_probabilities = model.predict_proba(input_data)
       
        print("\033[95m-------------------------------------------------------------\033[0m")
        print("\033[1mPhishing Site  : \033[96m", predicted_probabilities[0][0]*100, "%\033[0m")
        print("\033[1mLegitimate Site: \033[96m", predicted_probabilities[0][1]*100, "%\033[0m")
        print("\033[95m-------------------------------------------------------------\033[0m")


    global process_complete
    process_complete = True

def stop_loading():
    sys.stdout.flush()

print_banner()

url = input("\033[91m\033[1mEnter the URL to predict (e.g., https://example.com): \033[0m")

process_complete = False

loading_thread = threading.Thread(target=loading_animation)
loading_thread.start()

process_thread = threading.Thread(target=process, args=(url,))
process_thread.start()

process_thread.join()

stop_loading()

loading_thread.join()
