docker build -t bird-fuzzing .
docker run --name bird-fuzzing-container bird-fuzzing:latest
docker cp bird-fuzzing-container:/bird-fuzzing/output.txt ./outPut.txt
docker rm bird-fuzzing-container
cat outPut.txt