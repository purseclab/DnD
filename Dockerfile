FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive

# angr packages
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get -o APT::Immediate-Configure=0 install -y \
    virtualenvwrapper python3-dev python3-pip build-essential libxml2-dev \
    libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap \
    debian-archive-keyring libglib2.0-dev libpixman-1-dev qtdeclarative5-dev \
    binutils-multiarch nasm libc6:i386 libgcc1:i386 libstdc++6:i386 \
    libtinfo5:i386 zlib1g:i386 vim libssl-dev openjdk-8-jdk \
    && rm -rf /var/lib/apt/lists/*

# create and setup the dnd user
RUN useradd -s /bin/bash -m dnd
USER dnd
RUN echo 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh' >> /home/dnd/.bashrc && \
    echo 'workon dnd'>> /home/dnd/.bashrc

# create the virtual environment and get DnD code
RUN bash -c  "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && mkvirtualenv dnd"
RUN bash -c  "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon dnd && pip install ipython"
RUN bash -c "cd /home/dnd && git clone https://github.com/purseclab/DnD.git"

WORKDIR /home/dnd/DnD/

# install DnD
RUN bash -c  "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon dnd && pip install -r ./angr_env/requirements.txt"
RUN bash -c "cp angr_env/base.py ~/.virtualenvs/dnd/lib/python3.8/site-packages/claripy/ast/"

# install Patcherex
RUN bash -c  "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon dnd && cd patches && git clone https://github.com/angr/patcherex -b feat/evk --depth 1"
RUN bash -c  "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon dnd && pip install -U pip"
RUN bash -c  "source /usr/share/virtualenvwrapper/virtualenvwrapper.sh && workon dnd && cd patches/patcherex/ && pip install -e ."

