# generate log
slither . --exclude-informational --exclude-low &> ./docs/axiom-v1-contracts.log

# generate inheritance graph
slither . --print inheritance-graph
dot inheritance-graph.dot -Tpng -o axiom-v1-contracts.png
rm inheritance-graph.dot
mv axiom-v1-contracts.png ./docs/.

# run coverage report
# forge coverage &> ./docs/axiom-v1-contracts-coverage.log
forge coverage --report lcov
lcov --remove lcov.info  -o lcov.info 'test/*' 'script/*'
genhtml -o docs/coverage --branch-coverage lcov.info
rm lcov.info