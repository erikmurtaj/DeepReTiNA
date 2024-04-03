# DeepReTiNA
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](https://github.com/erikmurtaj/DeepReTiNA/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/Documentation-github-brightgreen.svg?style=for-the-badge)](https://www.unb.ca/cic/datasets/ids-2018.html)

DeepReTiNA stands for Real-Time Anomaly Detection IDS with a Deep and comprehensive study on the CSE-CIC-IDS2018 Dataset. 

The main contribution is the creation of a classifier model that has been integrated in the CICFlowMeter tool, originally developed by A. H. Lashkari ([CICFlowmeter-V4.0](https://github.com/ahlashkari/CICFlowMeter)) to detect Real-Time cyber-attacks and act as a simple Intrusion Detection System (IDS).

![alt text](https://github.com/erikmurtaj/DeepReTiNA/blob/main/screenshots/bruteforce_attack_screenshot.PNG?raw=true)

# User Usage
### 1. (Optional) Dataset Training Jupiter file

The dataset training has been developed in a Google Colab document and it is provided on the GitHub repository as a Juniper file (.ipynb). Simply import it into Google Colab to start working on it.

### 2. Tools Requirements
The modified version of the CICFlometer tool is developed in Java. Please make sure a Java JDK is installed in your machine additionally with Apache Maven.
Then clone this repository as follows:

```
git clone https://github.com/erikmurtaj/DeepReTiNA.git
```

#### Windows
Please make sure [WinCap](https://www.winpcap.org/install/default.htm) is installed in your machine. If not install the latest version and re-start the computer.

### 3. Install jnetpcap
#### Windows
Move to the DeepReTiNA/CICFlowMeter-classifier/jnetpcap/win/jnetpcap-1.4.r1425 folder. Then run:
```
 mvn install:install -file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

#### Linux
Move to the DeepReTiNA/CICFlowMeter-classifier/jnetpcap/linux/jnetpcap-1.4.r1425 folder. Then run:
```
sudo mvn install:install -file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

### 4. Tool Run
#### Eclipse
Run eclipse with sudo in Linux or as administrator in Windows. Then:
```
1. Right click App.java -> Run As -> Run Configurations -> Arguments -> VM arguments:
-Djava.library.path="* jnetpcap_path *" -> Run

2. Right click App.java -> Run As -> Java Application
```

Replace the “jnetpcap_path“ string with the following path for Linux:
```
"* pathtoproject */jnetpcap/linux/jnetpcap-1.4.r1425"
```
Or with the following string for Windows:
```
 "* pathtoproject *\jnetpcap\win\jnetpcap-1.4.r1425"
```

Where the “pathtoproject“ referes to the location the project have been saved, in particular of the _CICFlowmeter-classifier_ folder. For example:
```
 "C:\user\Documents\DeepRetina\CICFlowmeter-classifier"
```

#### IntelliJ IDEA
Open a Terminal in the IDE and for Linux run the following commands:
```
$ sudo bash
$ ./gradlew execute
```
Instead for Windows run:
```
$ gradlew execute
```

### 5. Make Package

#### Eclipse
At the project root run the following command:
```
mvn package
```

#### IntelliJ IDEA
Open a Terminal in the IDE and for Linux run the following command:
```
$ ./gradlew distZip
```
Instead for Windows run:
```
$  gradlew distZip
```

# Video Example of the Tool in action during a Bruteforce attack
https://github.com/erikmurtaj/DeepReTiNA/assets/50946517/4c644db1-4905-49aa-97ab-80f080ea85de





