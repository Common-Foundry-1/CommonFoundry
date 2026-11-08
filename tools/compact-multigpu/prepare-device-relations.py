"""Separate device-relations overlay; preserve previous qualified artifacts."""
import os
import shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
TOOLS=ROOT/'tools/compact-multigpu'
os.environ.setdefault('CMFD_COMPACT_BUILD_DIRECTORY',str(ROOT/'target/compact-relations-device-20261108'))
exec(compile((TOOLS/'prepare-shared-model.py').read_text(),'<shared-overlay>','exec'),{'__file__':str(TOOLS/'prepare-shared-model.py')})
OUT=Path(os.environ['CMFD_COMPACT_BUILD_DIRECTORY']).resolve()
GPU=OUT/'gpu-prover'
shutil.copyfile(TOOLS/'src/device_relations.rs',GPU/'src/device_relations.rs')
p=GPU/'src/bin/real_bank0_all_relations.rs'
text=p.read_text()
start=text.index("fn prove_bank_relations<'a>(")
end=text.index('\nfn read_base_input(',start)
body=text[start:end]
device=body.replace('fn prove_bank_relations<','fn prove_bank_relations_device<',1)
device=device.replace('let preactivation_reduced = reduce_batches(', 'let preactivation_reduced = device_relations::reduce_batches(')
device=device.replace('reduce_batches(&dynamic_tensor, BANK_VALUES,', 'device_relations::reduce_batches(&dynamic_tensor, BANK_VALUES,')
device=device.replace('let preactivation_evaluation = evaluate_matrix(', 'let preactivation_evaluation = device_relations::evaluate_matrix(')
old='''            &gpu_matrix_point.2,
        );'''
assert old in device
device=device.replace(old,'''            &gpu_matrix_point.2,
            scope,
        )?;''',1)
device=device.replace('cpu_matrix_claim_evaluation_seconds','device_matrix_claim_evaluation_seconds')
device=device.replace('        let weights = if ', '        drop(preactivation_reduced);\n        let weights = if ',1)
device=device.replace('let boundary=gpu_reductions::reduce(', 'let boundary=device_relations::reduce(')
a=device.index('        let mut input_values = Vec::with_capacity(')
b=device.index('        let matrix_started =',a)
device=device[:a]+'''        let (input_values,equality_values)=device_relations::matrix_inputs(&next_reduced,&boundary,&gpu_matrix_point.0,WIDTH,scope)?;
        eprintln!("bank={bank} repetition={repetition} device_matrix_input_build_seconds={:.6}",input_build_started.elapsed().as_secs_f64());
'''+device[b:]
device=device.replace('upload_ext(input_values, scope)','input_values').replace('upload_ext(equality_values, scope)','equality_values')
device=device.replace('let next_values = evaluate_rows(&next_reduced, &terminal_common);','let next_values = device_relations::evaluate_rows(&next_reduced, &terminal_common, scope)?;\n        drop(next_reduced);')
device=device.replace('let boundary_evaluation = evaluate_row(&boundary, &terminal_common);','let boundary_evaluation = device_relations::evaluate_scalar(&boundary, &terminal_common, scope)?;\n        drop(boundary);')
device=device.replace('cpu_next_and_boundary_evaluation_seconds','device_next_and_boundary_evaluation_seconds')
device=device.replace('upload_ext(next_values, scope)','Mle::new(next_values.into_inner().reshape([1,LAYERS]))')
marker='    let upload_started = Instant::now();'
assert marker in body
body=body.replace(marker,'''    if device_relations::enabled() {
        return prove_bank_relations_device(bank,statement,base_input,encoded_bank,resident,dynamic,boundary_activation,cpu_challenger,gpu_challenger,scope);
    }
'''+marker,1)
text=text[:start]+body+'\n'+device+text[end:]
text='#[path="../device_relations.rs"]\nmod device_relations;\n'+text
p.write_text(text,newline='\n')

# Reuse the exact field arithmetic and launch ABI already in batch_reduction.cu.
p=OUT/'batch_reduction.cu'
p.write_text(p.read_text()+'\n'+(TOOLS/'cuda/device-relations.inc').read_text(),newline='\n')

# Keep small per-claim coefficients alive and launch independent reductions
# before the single synchronization, instead of synchronizing after each row.
p=GPU/'src/real_v4_opening.rs'
text=p.read_text();start=text.index('pub fn prove_public_bank_opening_remote(');end=text.index('\nuse cmfd_consensus::',start)
body=text[start:end]
body=body.replace('    for (claim,power) in gpu_claims.iter().zip(&powers) {','    let mut device_coefficients=Vec::new();\n    for (claim,power) in gpu_claims.iter().zip(&powers) {',1)
body=body.replace('let row=dot_along_dim_view(dynamic_tensor.clone(),coefficients.as_view(),0);','let row=dot_along_dim_view(dynamic_tensor.clone(),coefficients.as_view(),0);\n            device_coefficients.push(coefficients);')
body=body.replace('traces.push(Mle::new(row.reshape([1,ROWS])));scope.synchronize_blocking()?;','traces.push(Mle::new(row.reshape([1,ROWS])));if !crate::device_relations::enabled(){scope.synchronize_blocking()?;}')
body=body.replace('    let sumcheck=crate::resident::distributed_sumcheck(', '    scope.synchronize_blocking()?;\n    drop(device_coefficients);\n    let sumcheck=crate::resident::distributed_sumcheck(',1)
old='''    let fixed_evaluations = crate::resident::fixed_evaluations(bank, &opening_point)?;
    let dynamic_evaluations = evaluate_dynamic_columns(dynamic_tensor, &opening_point, scope)?;'''
assert old in body
body=body.replace(old,'''    let (fixed_evaluations,dynamic_evaluations)=crate::resident::opening_evaluations(bank,&opening_point,dynamic_tensor,scope)?;''',1)
text=text[:start]+body+text[end:];p.write_text(text,newline='\n')
print('DEVICE_RELATIONS_OVERLAY_PREPARED')
