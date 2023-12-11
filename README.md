# DnD: A Cross-Architecture Deep Neural Network Decompiler

DND is the first compiler- and ISA-agnostic deep neural network (DNN) decompiler capable of extracting DNN models from compiled binaries. 

### Environment  
1. Create a Python virtual environment
2. `pip install -r ./angr_env/requirements.txt `
3. Move `./angr_env/base.py` to overwrite the counterpart in the virtual environment `claripy` (usually in `$USERNAME/.virtualenvs/$VIRTUALENVNAME/lib/python3.8/site-packages/claripy/ast/base.py`) 

### Usage
Run `python decompiler.py` to decompile a mnist binary on NXP imrt1050-evk board. Please check `decompiler.py` for more details.
