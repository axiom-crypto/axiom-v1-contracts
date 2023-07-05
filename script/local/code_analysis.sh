# generate log
slither . --exclude-informational --exclude-low &> ./docs/axiom-v1-contracts-slither.log

# generate inheritance graph
slither . --print inheritance-graph
dot inheritance-graph.dot -Tpng -o axiom-v1-contracts-inheritance-graph.png
rm inheritance-graph.dot
mv axiom-v1-contracts-inheritance-graph.png ./docs/.

# run coverage report
forge coverage &> ./docs/axiom-v1-contracts-coverage.log
