# PatrowlEnginesUtils

# Deployment commands
rm -rf dist/ build/ PatrowlEnginesUtils.egg-info
python setup.py sdist bdist_wheel
twine upload dist/* -u patrowl
