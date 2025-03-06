docker build -t bird-fuzzing .
docker run --name bird-fuzzing-container bird-fuzzing:latest
docker cp bird-fuzzing-container:/bird-fuzzing/output.txt .\output.txt
docker rm bird-fuzzing-container
type .\output.txt
