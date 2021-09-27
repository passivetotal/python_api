# Example Notebooks

## Getting Started

Each example notebook provides instructions and links to setup your API credentials and install extra Python packages that are optional for the library but may be required by a specific notebook. 

### Library Documentation

Complete docs are available in this repo and also at 
[passivetotal.readthedocs.io](https://passivetotal.readthedocs.io)

### About Jupyter Notebooks

The files in this directory are Jupyter Notebook files designed to run in an interactive Python session typically hosted in a web browser.

Learn more about the Jupyter project at [jupyter.org](https://jupyter.org)

### Viewing Notebooks on Github

If you are viewing this in a web browser on Github, simply click a link to each notebook file and Github will render it in your browser. You won't be able to run the code but you will see the text around the code, the code itself, and in some cases, the output of running the code.

For the optimal experience, download the notebook and run it in Jupyter, Visual Studio Code, or another tool capable of handling `.ipynb` files. 

### Downloading Notebooks

You can download notebooks by simply cloing this repo, or if you only need a specific file, look for the "RAW" button in the Github notebook viewer for a file, right-click or option-click the button, and select your browser's best option to download the file to your local system.

## Notebook Index

---
### [Trackers](Trackers%20-%20RiskIQ%20API.ipynb)

#### Features
* Explore capabiliites of the RiskIQ PassiveTotal **Trackerss** dataset
* Discover other sites where a client-side identifier is being used
* Find other hosts impersonating a focus host by detecting tracker
re-use on other sites.

---
### [Host Pairs](Host%20Pairs%20-%20RiskIQ%20API.ipynb)

#### Features
* Explore capabiliites of the RiskIQ PassiveTotal **Hostpairs** dataset
* Learn how to filter hostpairs to focus on foreign hosts
* Find inbound redirects targeting a site
* Find copycat sites using paired assets


---
### [Attack Surface & Vulnerabilty Intelligence](Attack%20Surface%20%26%20Vulnerability%20Intelligence%20-%20RiskIQ%20API)

#### Features
* Access to the __RiskIQ Illuminate__ Attack Surface Intelligence (ASI) product offering
* Finds impacted assets on your ASI and the Attack Surface of yoru third-party vendors.
* Enumerates CVEs for attack surface assets and lists which third-party vendors may be impacted.

#### Requirements
* Licensed access to RiskIQ Illuminate
* Pre-configured and authorized list of third-party vendors (optional)

---
### [Cyber Threat Intelligence (CTI)](Cyber%20Threat%20Intelligence%20%28CTI%29%20-%20RiskIQ%20API.ipynb)

#### Features
* Access threat actor profiles in the __RiskIQ Illuminate__ CTI product offering
* Obtains lists of IOCs for each actor profile
* Checks whether an IOC is listed in a threat actor profile

#### Requirements
* Licensed access to RiskIQ Illuminate CTI Module
