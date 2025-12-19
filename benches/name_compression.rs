use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gmdns::parser::{NameCompression, put_name};

fn bench_name_encode(c: &mut Criterion) {
    let mut names = Vec::with_capacity(1000);
    for i in 0..1000 {
        names.push(format!("host{i}.skype.com"));
    }

    c.bench_function("name/encode_1000", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(16 * 1024);
            let mut ctx = NameCompression::new();
            for name in &names {
                let _ = put_name(&mut buf, name, &mut ctx);
            }
            black_box(buf.len());
        });
    });
}

criterion_group!(benches, bench_name_encode);
criterion_main!(benches);
