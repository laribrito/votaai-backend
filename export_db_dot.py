#!/usr/bin/env python3
"""
Script utilitário para exportar o esquema do banco de dados em formato .dot (Graphviz)
e opcionalmente renderizar para SVG e PNG.
"""

import os
import sys
import sqlite3
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def export_relational_schema(output_dot: Path):
    """Gera o diagrama .dot a partir das tabelas físicas do banco SQLite."""
    db_path = BASE_DIR / "db.sqlite3"
    if not db_path.exists():
        print(f"Banco de dados {db_path} não encontrado.")
        return False

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' 
          AND name NOT LIKE 'sqlite_%' 
          AND name NOT IN ('django_migrations', 'django_content_type', 'django_session', 'django_admin_log')
        ORDER BY name;
    """)
    tables = [r[0] for r in cur.fetchall()]

    dot_lines = [
        'digraph DatabaseSchema {',
        '  graph [',
        '    rankdir=LR,',
        '    nodesep=0.6,',
        '    ranksep=1.2,',
        '    fontname="Helvetica,Arial,sans-serif",',
        '    fontsize=12,',
        '    pad="0.5",',
        '    splines=true,',
        '    concentrate=false,',
        '    bgcolor="#FFFFFF"',
        '  ];',
        '  node [shape=none, fontname="Helvetica,Arial,sans-serif", fontsize=10];',
        '  edge [fontname="Helvetica,Arial,sans-serif", fontsize=8, color="#475569", penwidth=1.2];',
        ''
    ]

    table_fks = {}

    for t in tables:
        cur.execute(f'PRAGMA table_info({t});')
        cols = cur.fetchall()
        cur.execute(f'PRAGMA foreign_key_list({t});')
        fks = cur.fetchall()
        table_fks[t] = fks

        if t.startswith('Domain_'):
            header_color = '#1E40AF' # Indigo/Blue
        elif t.startswith('auth_'):
            header_color = '#047857' # Emerald
        elif t.startswith('knox_'):
            header_color = '#B45309' # Amber
        else:
            header_color = '#334155' # Slate

        fk_cols = {fk[3] for fk in fks}

        rows = []
        rows.append(f'    <TR><TD COLSPAN="3" BGCOLOR="{header_color}" ALIGN="CENTER"><FONT COLOR="#FFFFFF"><B>{t}</B></FONT></TD></TR>')
        rows.append('    <TR BGCOLOR="#E2E8F0"><TD ALIGN="CENTER"><B>Key</B></TD><TD ALIGN="LEFT"><B>Column</B></TD><TD ALIGN="LEFT"><B>Type</B></TD></TR>')

        for i, c in enumerate(cols):
            _, cname, ctype, notnull, _, pk = c
            bg = '#FFFFFF' if i % 2 == 0 else '#F8FAFC'
            if pk:
                key_cell = '<TD ALIGN="CENTER"><FONT COLOR="#B45309"><B>PK</B></FONT></TD>'
            elif cname in fk_cols:
                key_cell = '<TD ALIGN="CENTER"><FONT COLOR="#2563EB"><B>FK</B></FONT></TD>'
            else:
                key_cell = '<TD ALIGN="CENTER"></TD>'
            
            req = ' *' if notnull and not pk else ''
            col_type = ctype if ctype else 'ANY'
            rows.append(f'    <TR BGCOLOR="{bg}">{key_cell}<TD PORT="{cname}" ALIGN="LEFT">{cname}{req}</TD><TD ALIGN="LEFT"><FONT COLOR="#64748B">{col_type}</FONT></TD></TR>')

        table_node = f'  "{t}" [label=<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">\n' + '\n'.join(rows) + '\n  </TABLE>>];'
        dot_lines.append(table_node)
        dot_lines.append('')

    for t, fks in table_fks.items():
        for fk in fks:
            _, _, to_table, from_col, to_col, _, _, _ = fk
            if to_table in tables:
                dot_lines.append(f'  "{t}":"{from_col}" -> "{to_table}":"{to_col}" [label=" {from_col} ", arrowhead=crow, arrowtail=tee, dir=both];')

    dot_lines.append('}')

    with open(output_dot, 'w', encoding='utf-8') as f:
        f.write('\n'.join(dot_lines))

    conn.close()
    return True

def export_django_models(domain_output: Path, all_output: Path):
    """Gera diagramas .dot através do Django ORM usando django-extensions."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'setup.settings')
    try:
        from setup import settings as project_settings
        if 'django_extensions' not in project_settings.INSTALLED_APPS:
            project_settings.INSTALLED_APPS = list(project_settings.INSTALLED_APPS) + ['django_extensions']
        
        import django
        django.setup()
        from django.core.management import call_command

        with open(domain_output, 'w', encoding='utf-8') as f:
            call_command(
                'graph_models',
                'Domain',
                '-E',
                '-X',
                'TimestampSchemaMixin,AbstractUser,AbstractBaseUser,PermissionsMixin',
                stdout=f
            )

        with open(all_output, 'w', encoding='utf-8') as f:
            call_command(
                'graph_models',
                '-a',
                '-g',
                '-E',
                '-X',
                'TimestampSchemaMixin,AbstractUser,AbstractBaseUser,PermissionsMixin',
                stdout=f
            )
        return True
    except Exception as e:
        print(f"Erro ao exportar modelos Django: {e}")
        return False

def render_graphviz(dot_path: Path):
    """Renderiza SVG e PNG se o comando dot estiver presente."""
    svg_path = dot_path.with_suffix('.svg')
    png_path = dot_path.with_suffix('.png')
    try:
        subprocess.run(['dot', '-Tsvg', str(dot_path), '-o', str(svg_path)], check=True)
        subprocess.run(['dot', '-Tpng', str(dot_path), '-o', str(png_path)], check=True)
        print(f"Renderizado: {svg_path.name} e {png_path.name}")
    except FileNotFoundError:
        print("Graphviz (dot) não instalado no sistema. Os arquivos .dot foram gerados com sucesso.")
    except Exception as e:
        print(f"Aviso ao renderizar {dot_path.name}: {e}")

def main():
    db_dot = BASE_DIR / "database.dot"
    domain_dot = BASE_DIR / "database_domain.dot"
    models_dot = BASE_DIR / "database_models.dot"

    print("1. Exportando esquema relacional físico das tabelas SQLite...")
    if export_relational_schema(db_dot):
        print(f"✓ Gerado: {db_dot.name}")
        render_graphviz(db_dot)

    print("\n2. Exportando modelos Django ORM...")
    if export_django_models(domain_dot, models_dot):
        print(f"✓ Gerado: {domain_dot.name}")
        render_graphviz(domain_dot)
        print(f"✓ Gerado: {models_dot.name}")
        render_graphviz(models_dot)

    print("\nExportação concluída!")

if __name__ == '__main__':
    main()

