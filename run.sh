#!/bin/bash

cp a2p1_security_layer.r2py repy/
cp a2p1_program.r2py repy/
cd repy/
python repy.py restrictions.default encasementlib.r2py a2p1_security_layer.r2py a2p1_program.r2py
cd ..