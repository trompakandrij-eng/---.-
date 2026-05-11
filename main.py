"""
Кросплатформений інтерактивний онлайн-дизасемблер
Курсова робота — Тромпак А. Ю., група ПМК-31
ЛНУ ім. Івана Франка, кафедра кібербезпеки
"""

import os
import uuid
import time
import tempfile
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import capstone
import lief

# ── Ініціалізація FastAPI ─────────────────────────────────────────────────────
app = FastAPI(title="Online Disassembler", version="1.0.0")

# Тимчасове сховище сесій (у пам'яті)
sessions = {}

# Максимальний розмір файлу (10 МБ)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Папка для статичних файлів (index.html)
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)


# ── Допоміжні функції ─────────────────────────────────────────────────────────

def detect_format(data: bytes) -> str:
    """Визначає формат бінарного файлу за магічними байтами."""
    if data[:4] == b'\x7fELF':
        return 'elf'
    elif data[:2] == b'MZ':
        return 'pe'
    elif data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                      b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        return 'macho'
    return 'unknown'


def get_capstone_arch(elf_binary):
    """Визначає архітектуру Capstone на основі ELF-заголовка."""
    machine = elf_binary.header.machine_type
    
    # Використовуємо числові значення для сумісності з усіма версіями LIEF
    machine_val = int(machine)
    
    if machine_val == 62:    # EM_X86_64
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, "x86-64"
    elif machine_val == 3:   # EM_386
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32, "x86-32"
    elif machine_val == 183: # EM_AARCH64
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, "ARM64"
    elif machine_val == 40:  # EM_ARM
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, "ARM32"
    else:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, f"unknown ({machine_val})"


def disassemble_section(code_bytes: bytes, base_addr: int, cs_arch, cs_mode):
    """Дизасемблює байти секції .text через Capstone Engine."""
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True  # Увімкнути детальну інформацію про інструкції
    
    instructions = []
    for insn in md.disasm(code_bytes, base_addr):
        # Визначити тип інструкції
        insn_type = "normal"
        if insn.group(capstone.CS_GRP_JUMP):
            insn_type = "jump"
        elif insn.group(capstone.CS_GRP_CALL):
            insn_type = "call"
        elif insn.group(capstone.CS_GRP_RET):
            insn_type = "ret"
        
        # Визначити ціль переходу (якщо є)
        target = None
        if insn_type in ("jump", "call") and insn.op_str.startswith("0x"):
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                pass
        
        instructions.append({
            "address": insn.address,
            "bytes": insn.bytes.hex(),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "size": insn.size,
            "type": insn_type,
            "target": target,
        })
    
    return instructions


def build_cfg(instructions):
    """Будує граф потоку керування (CFG) з дизасембльованих інструкцій."""
    if not instructions:
        return {"nodes": [], "edges": []}
    
    # Фаза 1: Знайти лідерів (початки базових блоків)
    leaders = {instructions[0]["address"]}  # Перша інструкція — завжди лідер
    addr_to_idx = {}
    
    for i, insn in enumerate(instructions):
        addr_to_idx[insn["address"]] = i
        
        if insn["type"] == "jump":
            # Ціль переходу — лідер
            if insn["target"] is not None:
                leaders.add(insn["target"])
            # Інструкція після переходу — лідер
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["address"])
        
        elif insn["type"] == "ret":
            # Інструкція після ret — лідер (якщо є)
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["address"])
        
        elif insn["type"] == "call":
            # Інструкція після call — лідер
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["address"])
    
    # Фаза 2: Побудувати базові блоки
    sorted_leaders = sorted(leaders)
    blocks = []
    leader_to_block = {}
    
    for leader_addr in sorted_leaders:
        if leader_addr not in addr_to_idx:
            continue
        
        start_idx = addr_to_idx[leader_addr]
        block_insns = []
        
        for j in range(start_idx, len(instructions)):
            insn = instructions[j]
            block_insns.append(insn)
            
            # Блок закінчується на: jump, ret, call, або наступна інструкція — лідер
            if insn["type"] in ("jump", "ret"):
                break
            if insn["type"] == "call":
                break
            if j + 1 < len(instructions) and instructions[j + 1]["address"] in leaders:
                break
        
        if block_insns:
            block_id = f"block_{leader_addr:#x}"
            block = {
                "id": block_id,
                "start_addr": block_insns[0]["address"],
                "end_addr": block_insns[-1]["address"],
                "insn_count": len(block_insns),
                "instructions": block_insns,
            }
            blocks.append(block)
            leader_to_block[leader_addr] = block_id
    
    # Фаза 3: Побудувати ребра
    edges = []
    for block in blocks:
        last_insn = block["instructions"][-1]
        last_addr = last_insn["address"]
        next_addr = last_addr + last_insn["size"]
        
        if last_insn["type"] == "jump":
            # Визначити чи це умовний перехід
            conditional_mnemonics = {
                "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns",
                "jp", "jnp", "jcxz", "jecxz", "jrcxz",
                "b.eq", "b.ne", "b.gt", "b.lt", "b.ge", "b.le",  # ARM64
            }
            is_conditional = last_insn["mnemonic"].lower() in conditional_mnemonics
            
            if last_insn["target"] is not None and last_insn["target"] in leader_to_block:
                edges.append({
                    "source": block["id"],
                    "target": leader_to_block[last_insn["target"]],
                    "type": "conditional_true" if is_conditional else "unconditional",
                })
            
            # Умовний перехід має також false-гілку (наступна інструкція)
            if is_conditional and next_addr in leader_to_block:
                edges.append({
                    "source": block["id"],
                    "target": leader_to_block[next_addr],
                    "type": "conditional_false",
                })
        
        elif last_insn["type"] == "call":
            # Після call продовжуємо до наступного блоку
            if next_addr in leader_to_block:
                edges.append({
                    "source": block["id"],
                    "target": leader_to_block[next_addr],
                    "type": "call_fallthrough",
                })
        
        elif last_insn["type"] == "normal":
            # Звичайна інструкція → переходимо до наступного блоку
            if next_addr in leader_to_block:
                edges.append({
                    "source": block["id"],
                    "target": leader_to_block[next_addr],
                    "type": "fallthrough",
                })
    
    # Формат для Cytoscape.js
    nodes = []
    for block in blocks:
        # Перші кілька інструкцій для підпису вузла
        preview = "; ".join(
            f"{ins['mnemonic']} {ins['op_str']}" 
            for ins in block["instructions"][:4]
        )
        if len(block["instructions"]) > 4:
            preview += f"; ... (+{len(block['instructions']) - 4})"
        
        nodes.append({
            "data": {
                "id": block["id"],
                "label": f"{block['start_addr']:#x}\n({block['insn_count']} insns)",
                "start_addr": block["start_addr"],
                "end_addr": block["end_addr"],
                "insn_count": block["insn_count"],
                "preview": preview,
            }
        })
    
    cy_edges = []
    for i, edge in enumerate(edges):
        cy_edges.append({
            "data": {
                "id": f"edge_{i}",
                "source": edge["source"],
                "target": edge["target"],
                "type": edge["type"],
            }
        })
    
    return {"nodes": nodes, "edges": cy_edges}


# ── API Ендпоінти ─────────────────────────────────────────────────────────────

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Завантажити та проаналізувати ELF-файл."""
    
    # Зчитати файл
    data = await file.read()
    
    # Перевірка розміру
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Файл занадто великий (максимум 10 МБ)")
    
    # Перевірка формату
    fmt = detect_format(data)
    if fmt == 'unknown':
        raise HTTPException(status_code=422, detail="Невідомий формат файлу. Підтримуються: ELF.")
    if fmt != 'elf':
        raise HTTPException(
            status_code=422,
            detail=f"Формат '{fmt.upper()}' розпізнано, але поточна версія підтримує лише ELF."
        )
    
    # Зберегти у тимчасовий файл для LIEF
    tmp_path = os.path.join(tempfile.gettempdir(), f"disasm_{uuid.uuid4().hex}")
    with open(tmp_path, 'wb') as f:
        f.write(data)
    
    try:
        # Парсинг ELF
        start_time = time.time()
        binary = lief.parse(tmp_path)
        parse_time = (time.time() - start_time) * 1000  # мс
        
        if binary is None:
            raise HTTPException(status_code=422, detail="Не вдалося розпарсити ELF-файл.")
        
        # Визначити архітектуру
        cs_arch, cs_mode, arch_name = get_capstone_arch(binary)
        
        # Знайти секцію .text
        text_section = None
        for section in binary.sections:
            if section.name == ".text":
                text_section = section
                break
        
        if text_section is None:
            raise HTTPException(status_code=422, detail="Секцію .text не знайдено у файлі.")
        
        # Отримати байти та адресу секції .text
        code_bytes = bytes(text_section.content)
        base_addr = text_section.virtual_address
        
        # Дизасемблювання
        start_time = time.time()
        instructions = disassemble_section(code_bytes, base_addr, cs_arch, cs_mode)
        disasm_time = (time.time() - start_time) * 1000
        
        # Побудова CFG
        start_time = time.time()
        cfg = build_cfg(instructions)
        cfg_time = (time.time() - start_time) * 1000
        
        # Інформація про секції
        sections_info = []
        for section in binary.sections:
            if section.name:
                sections_info.append({
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "size": section.size,
                    "offset": section.offset,
                })
        
        # Інформація про символи
        symbols = []
        for sym in binary.symbols:
            if sym.name and sym.value > 0:
                symbols.append({
                    "name": sym.name,
                    "address": sym.value,
                    "type": str(sym.type).split('.')[-1] if sym.type else "unknown",
                })
        
        # Зберегти сесію
        session_id = uuid.uuid4().hex[:12]
        sessions[session_id] = {
            "filename": file.filename,
            "format": "ELF64" if str(binary.header.identity_class).endswith("CLASS64") else "ELF32",
            "architecture": arch_name,
            "entry_point": binary.header.entrypoint,
            "sections": sections_info,
            "symbols": symbols[:200],  # Обмежити кількість символів
            "instructions": instructions,
            "cfg": cfg,
            "timing": {
                "parse_ms": round(parse_time, 1),
                "disasm_ms": round(disasm_time, 1),
                "cfg_ms": round(cfg_time, 1),
                "total_ms": round(parse_time + disasm_time + cfg_time, 1),
            },
            "stats": {
                "total_instructions": len(instructions),
                "cfg_nodes": len(cfg["nodes"]),
                "cfg_edges": len(cfg["edges"]),
                "text_section_size": len(code_bytes),
            }
        }
        
        # Відповідь (без інструкцій та CFG — вони окремим запитом)
        return {
            "session_id": session_id,
            "filename": file.filename,
            "format": sessions[session_id]["format"],
            "architecture": arch_name,
            "entry_point": hex(binary.header.entrypoint),
            "sections": sections_info,
            "symbols_count": len(symbols),
            "timing": sessions[session_id]["timing"],
            "stats": sessions[session_id]["stats"],
        }
    
    finally:
        # Видалити тимчасовий файл
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.get("/api/disassemble/{session_id}")
async def get_disassembly(session_id: str):
    """Отримати результати дизасемблювання."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Сесію не знайдено.")
    
    session = sessions[session_id]
    return {
        "session_id": session_id,
        "architecture": session["architecture"],
        "total_instructions": len(session["instructions"]),
        "instructions": session["instructions"],
    }


@app.get("/api/cfg/{session_id}")
async def get_cfg(session_id: str):
    """Отримати граф потоку керування."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Сесію не знайдено.")
    
    session = sessions[session_id]
    return {
        "session_id": session_id,
        "cfg": session["cfg"],
        "stats": {
            "nodes": len(session["cfg"]["nodes"]),
            "edges": len(session["cfg"]["edges"]),
        }
    }


@app.get("/api/export/{session_id}")
async def export_results(session_id: str, format: str = "text"):
    """Експортувати результати аналізу."""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Сесію не знайдено.")
    
    session = sessions[session_id]
    
    if format == "json":
        return {
            "filename": session["filename"],
            "format": session["format"],
            "architecture": session["architecture"],
            "entry_point": hex(session["entry_point"]),
            "sections": session["sections"],
            "instructions": session["instructions"],
            "cfg": session["cfg"],
            "timing": session["timing"],
        }
    else:
        # Текстовий формат (подібно до objdump -d)
        lines = [
            f"; Файл: {session['filename']}",
            f"; Формат: {session['format']}",
            f"; Архітектура: {session['architecture']}",
            f"; Точка входу: {hex(session['entry_point'])}",
            f"; Дизасемблер: Capstone Engine + LIEF",
            "",
            "Disassembly of section .text:",
            "",
        ]
        
        for insn in session["instructions"]:
            addr = f"{insn['address']:016x}" if "64" in session["architecture"] else f"{insn['address']:08x}"
            bytes_str = insn["bytes"].ljust(24)
            lines.append(f"  {addr}:  {bytes_str}  {insn['mnemonic']:<8} {insn['op_str']}")
        
        return {"text": "\n".join(lines)}


# ── Статичні файли та головна сторінка ────────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    """Головна сторінка."""
    return FileResponse(str(STATIC_DIR / "index.html"))


# ── Запуск сервера ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  Онлайн-дизасемблер v1.0")
    print("  Курсова робота — Тромпак А. Ю., ПМК-31")
    print("=" * 60)
    print()
    print("  Відкрий у браузері: http://127.0.0.1:8000")
    print("  Для зупинки натисни Ctrl+C")
    print()
    uvicorn.run(app, host="127.0.0.1", port=8000)
