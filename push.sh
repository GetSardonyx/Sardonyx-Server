#!/bin/bash


echo Commit Descriptor

read cmit

echo Adding...

git add .

echo Committing...

git commit -m "$cmit"

echo Pushing...

git push

echo Done!
