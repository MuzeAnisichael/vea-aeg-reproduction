# Paper-to-Code Mapping

| Paper element | Repository location | Status |
| --- | --- | --- |
| Dangerous function list | `src/vea_aeg/dangerous_functions.py` | Implemented |
| PLT extraction | `src/vea_aeg/static_analysis.py` | Implemented |
| CFG construction | `src/vea_aeg/static_analysis.py` | Implemented through angr |
| CDG/DDG backward slicing | `src/vea_aeg/static_analysis.py` | Approximation only |
| Suspicious path pruning | `src/vea_aeg/path_optimizer.py` | Scaffold |
| Unconstrained-state detection | `src/vea_aeg/exploitability.py` | Scaffold |
| IP/BP symbolic rules | `src/vea_aeg/exploitability.py` | Implemented |
| Symbolic memory read/write rules | `src/vea_aeg/exploitability.py` | Implemented helper |
| radare2 resource collection | `src/vea_aeg/exploit_builder.py` | Scaffold |
| Exploit strategy table | `src/vea_aeg/exploit_builder.py` | Partial |
| Stack pointer redirection | `src/vea_aeg/exploit_builder.py` | TODO |
| Payload generation | `src/vea_aeg/exploit_builder.py` | TODO |
| Experiment table reproduction | `docs/reproduction_plan.md` | TODO |

