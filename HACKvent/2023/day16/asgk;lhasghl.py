from z3 import Int, Solver
from itertools import combinations
# Var for each letter
S, E, N, D, M, O, R, Y = [Int(c) for c in 'SENDMORY']

solver = Solver()

# each letter must be between 0-9
for letter in [S, E, N, D, M, O, R, Y]:
    solver.add(0 <= letter, letter <= 9)
# each letter cannot be the same as any other letter
for pair in combinations([S, E, N, D, M, O, R, Y], 2):
    solver.add(pair[0] != pair[1])

# specific assignment for M
solver.add(M == 1)

# the values at different unit places need to be multiplied to account for the original challenge
#    SEND
#  + MORE
# = MONEY
solver.add(1000 * S + 100 * E + 10 * N + D + 1000 * M + 100 * O + 10 * R + E == 10000 * M + 1000 * O + 100 * N + 10 * E + Y)

# Check for Satisfiability
if solver.check():
    model = solver.model()
    # get value of each letter
    for letter in [S, E, N, D, M, O, R, Y]:
        print(f"{letter} = {model[letter].as_long()}")