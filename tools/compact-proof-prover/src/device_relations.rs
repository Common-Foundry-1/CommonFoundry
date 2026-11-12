//! Exact device-side relation inputs; only public scalar claims return to CPU.
use super::*;
use anyhow::Context as _;

unsafe extern "C" {
    fn cmfd_batch_layer_reduction_kernel() -> sp1_gpu_sys::runtime::KernelPtr;
    fn cmfd_relation_inputs_kernel() -> sp1_gpu_sys::runtime::KernelPtr;
}

pub(crate) fn enabled() -> bool {
    std::env::var("CMFD_DEVICE_RELATIONS").as_deref() == Ok("1")
}

pub(crate) fn reduce_batches(
    dynamic: &TensorView<'_, Felt, TaskScope>,
    offset: usize,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<DeviceTensor<Ext>> {
    ensure!(
        offset
            .checked_add(BANK_VALUES)
            .is_some_and(|end| end <= dynamic.total_len()),
        "device batch range"
    );
    let view = unsafe {
        TensorView::from_raw_parts(
            dynamic.as_ptr().add(offset),
            Dimensions::try_from([BANK_VALUES])?,
            scope.clone(),
        )
    };
    let coefficients = Mle::<Ext>::partial_lagrange(point);
    reduce(
        view,
        coefficients.guts().as_slice(),
        LAYERS,
        BATCH,
        WIDTH,
        scope,
    )
}

pub(crate) fn reduce(
    source: TensorView<'_, Felt, TaskScope>,
    coefficients: &[Ext],
    layers: usize,
    batch: usize,
    width: usize,
    scope: &TaskScope,
) -> Result<DeviceTensor<Ext>> {
    let count = gpu_reductions::checked_shape(
        source.total_len(),
        coefficients.len(),
        layers,
        batch,
        width,
    )?;
    ensure!(
        size_of::<Felt>() == 4 && size_of::<Ext>() == 16,
        "device relation field ABI"
    );
    let coefficients = DeviceTensor::from_host(&Tensor::from(coefficients.to_vec()), scope)?;
    let mut output = DeviceTensor::<Ext>::with_sizes_in([layers, width], scope.clone());
    unsafe {
        output.assume_init();
        let arguments = args!(
            source.as_ptr(),
            coefficients.as_ptr(),
            output.as_mut_ptr(),
            layers,
            batch,
            width
        );
        scope.launch_kernel(
            cmfd_batch_layer_reduction_kernel(),
            u32::try_from(count.div_ceil(256))?,
            256u32,
            &arguments,
            0,
        )?;
    }
    // The small coefficient buffer must outlive the kernel that reads it.
    scope.synchronize_blocking()?;
    Ok(output)
}

pub(crate) fn evaluate_rows(
    source: &DeviceTensor<Ext>,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<DeviceTensor<Ext>> {
    let coefficients = Mle::<Ext>::partial_lagrange(point);
    let width = coefficients.guts().as_slice().len();
    ensure!(
        source.total_len() > 0 && source.total_len() % width == 0,
        "device row evaluation geometry"
    );
    let coefficients = DeviceTensor::from_host(
        &Tensor::from(coefficients.guts().as_slice().to_vec()),
        scope,
    )?;
    let rows = source.total_len() / width;
    let view = unsafe {
        TensorView::from_raw_parts(
            source.as_ptr(),
            Dimensions::try_from([rows, width])?,
            scope.clone(),
        )
    };
    let result = dot_along_dim_view(view, coefficients.as_view(), 1);
    scope.synchronize_blocking()?;
    Ok(DeviceTensor::from_raw(result))
}

pub(crate) fn evaluate_scalar(
    source: &DeviceTensor<Ext>,
    point: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Ext> {
    ensure!(
        source.total_len()
            == 1usize
                .checked_shl(point.len() as u32)
                .context("device point dimension")?,
        "device scalar geometry"
    );
    let value = evaluate_rows(source, point, scope)?;
    ensure!(value.total_len() == 1, "device scalar output");
    Ok(value.to_host()?.as_slice()[0])
}

pub(crate) fn evaluate_matrix(
    source: &DeviceTensor<Ext>,
    layer: &Point<Ext>,
    output: &Point<Ext>,
    scope: &TaskScope,
) -> Result<Ext> {
    let rows = evaluate_rows(source, output, scope)?;
    evaluate_scalar(&rows, layer, scope)
}

pub(crate) fn matrix_inputs(
    next: &DeviceTensor<Ext>,
    boundary: &DeviceTensor<Ext>,
    point: &Point<Ext>,
    width: usize,
    scope: &TaskScope,
) -> Result<(Mle<Ext, TaskScope>, Mle<Ext, TaskScope>)> {
    let coefficients = Mle::<Ext>::partial_lagrange(point);
    let layers = coefficients.guts().as_slice().len();
    let count = layers
        .checked_mul(width)
        .context("device input geometry overflow")?;
    ensure!(
        width > 0 && next.total_len() == count && boundary.total_len() == width,
        "device input geometry"
    );
    let coefficients = DeviceTensor::from_host(
        &Tensor::from(coefficients.guts().as_slice().to_vec()),
        scope,
    )?;
    let mut input = DeviceTensor::<Ext>::with_sizes_in([1, count], scope.clone());
    let mut equality = DeviceTensor::<Ext>::with_sizes_in([1, count], scope.clone());
    unsafe {
        input.assume_init();
        equality.assume_init();
        let arguments = args!(
            next.as_ptr(),
            boundary.as_ptr(),
            coefficients.as_ptr(),
            input.as_mut_ptr(),
            equality.as_mut_ptr(),
            count,
            width
        );
        scope.launch_kernel(
            cmfd_relation_inputs_kernel(),
            u32::try_from(count.div_ceil(256))?,
            256u32,
            &arguments,
            0,
        )?;
    }
    scope.synchronize_blocking()?;
    Ok((
        Mle::new(input.into_inner()),
        Mle::new(equality.into_inner()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use slop_algebra::AbstractExtensionField;
    #[test]
    #[ignore = "requires a reserved GPU"]
    fn device_inputs_and_evaluations_match_cpu_exactly() {
        run_sync_in_place(|scope| -> Result<()> {
            for (layers, batch, width) in [(1usize, 2usize, 8usize), (4, 8, 16), (128, 128, 4096)] {
                let layer = Point::from(
                    (0..layers.ilog2())
                        .map(|i| challenge(i as usize + 3))
                        .collect::<Vec<_>>(),
                );
                let output = Point::from(
                    (0..width.ilog2())
                        .map(|i| challenge(i as usize + 11))
                        .collect::<Vec<_>>(),
                );
                let batch_point = Point::from(
                    (0..batch.ilog2())
                        .map(|i| challenge(i as usize + 17))
                        .collect::<Vec<_>>(),
                );
                let source = (0..layers * batch * width)
                    .map(|i| Felt::from_canonical_usize((i * 37 + 19) % 65521))
                    .collect::<Vec<_>>();
                let coefficients = Mle::<Ext>::partial_lagrange(&batch_point);
                let expected = (0..layers * width)
                    .map(|i| {
                        let (l, c) = (i / width, i % width);
                        (0..batch)
                            .map(|b| {
                                Ext::from_base(source[(l * batch + b) * width + c])
                                    * coefficients.guts().as_slice()[b]
                            })
                            .sum::<Ext>()
                    })
                    .collect::<Vec<_>>();
                let source = DeviceTensor::from_host(&Tensor::from(source), &scope)?;
                let reduced = reduce(
                    source.as_view(),
                    coefficients.guts().as_slice(),
                    layers,
                    batch,
                    width,
                    &scope,
                )?;
                assert_eq!(reduced.to_host()?.as_slice(), expected.as_slice());
                assert_eq!(
                    evaluate_matrix(&reduced, &layer, &output, &scope)?,
                    super::super::evaluate_matrix(&expected, &layer, &output)
                );
                let rows = evaluate_rows(&reduced, &output, &scope)?;
                assert_eq!(
                    rows.to_host()?.as_slice(),
                    super::super::evaluate_rows(&expected, &output)
                );
                let boundary = expected[..width].to_vec();
                let boundary_device =
                    DeviceTensor::from_host(&Tensor::from(boundary.clone()), &scope)?;
                let (input, equality) =
                    matrix_inputs(&reduced, &boundary_device, &layer, width, &scope)?;
                let expected_input = boundary
                    .iter()
                    .chain(expected[..(layers - 1) * width].iter())
                    .copied()
                    .collect::<Vec<_>>();
                let expected_equality = Mle::<Ext>::partial_lagrange(&layer)
                    .guts()
                    .as_slice()
                    .iter()
                    .flat_map(|v| std::iter::repeat_n(*v, width))
                    .collect::<Vec<_>>();
                assert_eq!(
                    DeviceTensor::copy_to_host(input.guts())?.as_slice(),
                    expected_input
                );
                assert_eq!(
                    DeviceTensor::copy_to_host(equality.guts())?.as_slice(),
                    expected_equality
                );
                assert_eq!(
                    evaluate_scalar(&boundary_device, &output, &scope)?,
                    super::super::evaluate_row(&boundary, &output)
                );
                assert!(
                    matrix_inputs(&reduced, &boundary_device, &layer, width + 1, &scope).is_err()
                );
                drop(source);
                drop(reduced);
                drop(rows);
                drop(boundary_device);
                drop(input);
                drop(equality);
                scope.synchronize_blocking()?;
            }
            Ok(())
        })
        .unwrap()
        .unwrap();
    }
    fn challenge(i: usize) -> Ext {
        Ext::from_base_slice(&[
            Felt::from_canonical_usize(i),
            Felt::from_canonical_usize(i + 1),
            Felt::one(),
            Felt::from_canonical_usize(i + 7),
        ])
    }
}
