import setuptools
from ws_tool_name._version import __version__, __tool_name__, __description__

tool_name = 'tool_name'

setuptools.setup(
    name=f"ws_{__tool_name__}",
    entry_points={
        'console_scripts': [
            f'{tool_name}=ws_{tool_name}.{tool_name}:main'
        ]},
    version=__version__,
    author="WhiteSource Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description=__description__,
    url='https://github.com/whitesource-ps/ws-tool-name',
    license='LICENSE',
    packages=setuptools.find_packages(),
    python_requires='>=3.7',
    install_requires=[line.strip() for line in open("requirements.txt").readlines()],
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
