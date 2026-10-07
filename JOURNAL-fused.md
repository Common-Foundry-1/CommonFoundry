# JOURNAL — fused GEMM+reduce (ветка fused от df45de5)

Цель: одно ядро int8 GEMM (tensor cores) + reduce слоя в эпилоге, int32-аккумуляторы не уходят в DRAM.
База (4070 Ti, batch 32, opt1): GEMM 928.6 мс + reduce 299.6 мс = 1231 мс/пачка.

## Шаг a — чередование лимбов (m = 4·row + limb)
- Меняются ТОЛЬКО: write_centered_limbs (запись) и чтение аккумуляторов в reduce_layer/reduce_layer_batch.
- GEMM layout-агностичен (строка m A ↔ строка m C), поэтому CUTLASS/dp4a не трогаем.
- Новый layout: лимб j ячейки (r,c) лежит по смещению (4r+j)·width + c (внутри lane-блока 4·cells).
- Проверка: opt_test.sh → determinism 0 расхождений, digest 32/32, побайтово как раньше.
