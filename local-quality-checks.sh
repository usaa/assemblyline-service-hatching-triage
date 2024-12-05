SRCDIR=./hatching

echo --- flake8 --- 
flake8 $SRCDIR --count --max-complexity=10 --max-line-length=127 --show-source --statistics

echo --- pylint --- 
python3 -m pylint -f colorized --load-plugins=pylint.extensions.mccabe --max-complexity 25 --fail-under=8 $SRCDIR

echo --- mypy --- 
python3 -m mypy $SRCDIR --cache-dir=/dev/null