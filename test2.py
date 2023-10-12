numberOfUsers=25
usersTupples = [[[0 for _ in range(4)] for _ in range(2)] for _ in range(numberOfUsers)] # Three values (mr, tv and type) , two periods and 10 users

try:
    with open("/Users/emanahmed/Documents/GitHub/ZPPB-LEM2/data/input-P0-1.txt", 'r') as file:
        u,p,v=0,0,0
        n=0
        for line in file:
            numbers = line.split()
            for i in range(numberOfUsers*8):
                print(numbers[i])
                usersTupples[u][p][v]= int(numbers[i]) # u is the user ID , p is the period number , v is the value ( mr,tv or type)
                v+=1
                n+=1
                if n==4: v,p=0,1
                elif n==8:
                    v,p,n=0,0,0
                    u+=1
except FileNotFoundError:
    print(f"The file '{file_path}' was not found.")
