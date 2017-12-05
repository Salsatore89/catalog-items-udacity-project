# Sports Catalog - An udacity project

## Overview
Sports Catalog is an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own categories & items.

## Components
* Routing and templating made with **Flask**
* Uses **SQLAlchemy** to communicate with the back-end db
* **RESTful API** endpoints that return json files
* Uses **Google & Facebook Login** to authenticate users
 authenticated users can create and edit items
* Front-end forms and webpages built with **Boostrap**

## How to Run

#### PreRequisites
  * [Python ~2.7](https://www.python.org/)
  * [Vagrant](https://www.vagrantup.com/)
  * [VirtualBox](https://www.virtualbox.org/)

#### Setup Project
  1. Install Vagrant and VirtualBox
  2. Download or Clone [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm) repository.
  3. Find the catalog folder and replace it with the content of this current repository, by either downloading or cloning it from
  [Here](https://github.com/Salsatore89/catalog-items-udacity-project).

#### Launch Project
  1. Launch the Vagrant VM using command:

  ```
    $ vagrant up
  ```
  2. Run your application within the VM

  ```
    $ python /vagrant/catalog/project.py
  ```
  3. Access and test your application by visiting [http://localhost:5000](http://localhost:5000).
