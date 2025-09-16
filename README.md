What is a Black Box?

In Cybersecurity and Machine Learning, a black box is a system or application where we can only observe the input and outputs of the system without knowledge of its inner workings, structure, or source code. 

Our goal here is to build a machine learning model that can classify samples as malware or benign.

The requirements for the model are:

- False Positive Rate (FPR) < 1%  
- True Positive Rate (TPR) > 95%  

---

Steps to test the model:

1. Extract the ember datasets 2017 and 2018:  
    wget https://ember.elastic.co/ember_dataset_2017_2.tar.bz2  
    tar -xvjf ember_dataset_2017_2.tar.bz2  

    wget https://ember.elastic.co/ember_dataset_2018_2.tar.bz2  
    tar -xvjf ember_dataset_2018_2.tar.bz2  

2. Generate the `nfs_libraries_functions_nostrings.pickle`:  
    python -m train.train_classifier  

3. Move the pickle file into the correct location:  
    mv nfs_libraries_functions_nostrings.pickle defender/defender/models/  

4. Install dependencies locally if you want to run training or scripts outside Docker:  
    pip install -r requirements.txt  

5. Build the Docker image:  
    docker build -t ember .  

6. Run the Docker container (defaults to the Ember model):  
    docker run -itp 8080:8080 ember  
