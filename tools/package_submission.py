"""将已提交源码、报告与视频打包；姓名学号可在提交前补充。"""
import argparse
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def package(output, name='', student_id=''):
    output = Path(output).resolve()
    prefix = f'{name}_{student_id}' if name and student_id else '实验1A'
    folder = f'{prefix}_EX1A' if name and student_id else '实验1A'
    source = f'{prefix}_ex1A_src' if name and student_id else '实验1A_src'
    report = output / '实验1A_report.pdf'
    video = output / '实验1A_play.mp4'
    if not report.is_file() or not video.is_file():
        raise ValueError('请先生成实验报告和演示视频。')
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf-8').split('\0')
    target = output / '实验1A_提交包.zip'
    expected = []
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for relative in filter(None, tracked):
            path = ROOT / relative
            if not path.is_file():
                raise ValueError(f'已跟踪文件不存在：{relative}')
            member = f'{folder}/{source}/{relative}'
            archive.write(path, member)
            expected.append(member)
        for path, suffix in [(report, 'report.pdf'), (video, 'play.mp4')]:
            member = f'{folder}/{prefix}_ex1A_{suffix}' if name and student_id else f'{folder}/实验1A_{suffix}'
            archive.write(path, member)
            expected.append(member)
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None or sorted(archive.namelist()) != sorted(expected):
            raise RuntimeError('ZIP 完整性验证失败。')
        if any(info.flag_bits & 1 for info in archive.infolist()):
            raise RuntimeError('提交 ZIP 不应加密。')
    return dict(path=str(target), entries=len(expected), source_files=len(expected) - 2,
                bytes=target.stat().st_size, encrypted=False, identity_filled=bool(name and student_id))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default=str(ROOT / 'output'))
    parser.add_argument('--name', default='')
    parser.add_argument('--student-id', default='')
    args = parser.parse_args()
    print(json.dumps(package(args.output, args.name, args.student_id), ensure_ascii=True))
