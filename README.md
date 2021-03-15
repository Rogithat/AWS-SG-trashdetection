<p align="center">
  <img alt="gitlab" src="https://i.imgur.com/OrDa8Ui.png" width="250px" float="center"/>
</p>

<h1 align="center">Welcome to AWS-TrashDetection</h1>

>
> AWS-SG-trashdetection
>

## ➤ Description

A script to find and prune AWS Security Groups trash entries.

To use it, you must login in to aws console using:
aws configure or exporting your ACCESS_KEY, SESSION_TOKEN, and SECRET_KEY environment variables

Then replace "your_regex" variable with a regex that match description with rules you want to delete.

To run this you'll need:
    * Python
        * Boto3
    * Docker
    * K8S to run the CronJob


## ➤ Features

* Python script
* Dockerfile
* K8s CronJob (in development)

Please feel free to contribute or rate my coding.

