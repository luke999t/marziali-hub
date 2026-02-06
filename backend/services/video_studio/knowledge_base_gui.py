"""
Knowledge Base GUI - Visualizzatore Knowledge Base
====================================================

GUI Tkinter per visualizzare e gestire knowledge base:
- TreeView navigabile (forms/sequences/patterns/qa)
- Search e filtri
- Stats panel
- Import/Export
- Preview dettagli

Author: AI Assistant
Date: 2025-11-06
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
from pathlib import Path
from typing import Dict, Any, List
import sys

# Import manager
sys.path.insert(0, str(Path(__file__).parent))
from knowledge_base_manager import KnowledgeBaseManager


class KnowledgeBaseGUI:
    """GUI per visualizzare e gestire knowledge base"""

    def __init__(self, root):
        self.root = root
        self.root.title("🗂️ Knowledge Base Manager - Martial Arts RAG")
        self.root.geometry("1400x900")

        # Manager
        self.manager = KnowledgeBaseManager()

        # Current data
        self.current_filter = "all"
        self.current_search = ""

        # Setup UI
        self._setup_ui()

        # Load default if exists
        default_path = Path(r"C:\Users\utente\Desktop\knowledge_base_martial_arts\merged_knowledge.json")
        if default_path.exists():
            self.load_knowledge_base(default_path)

    def _setup_ui(self):
        """Setup complete UI"""

        # ==================== TOP TOOLBAR ====================
        toolbar = ttk.Frame(self.root, padding=10)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        # Import button
        ttk.Button(toolbar, text="📥 Import JSON", command=self.import_json).pack(side=tk.LEFT, padx=5)

        # Import directory
        ttk.Button(toolbar, text="📂 Import Directory", command=self.import_directory).pack(side=tk.LEFT, padx=5)

        # Export button
        ttk.Button(toolbar, text="💾 Export Merged", command=self.export_merged).pack(side=tk.LEFT, padx=5)

        # Validate button
        ttk.Button(toolbar, text="✅ Validate", command=self.validate_kb).pack(side=tk.LEFT, padx=5)

        # Separator
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        # Search bar
        ttk.Label(toolbar, text="🔍 Search:").pack(side=tk.LEFT, padx=5)

        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.apply_filters())

        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Filter dropdown
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=5)

        self.filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(toolbar, textvariable=self.filter_var, width=15,
                                     values=["all", "forms", "sequences", "patterns", "qa_pairs"])
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())

        # Refresh button
        ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_view).pack(side=tk.LEFT, padx=5)

        # ==================== MAIN CONTENT ====================
        main_frame = ttk.Frame(self.root)
        main_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # LEFT PANEL: TreeView
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(left_panel, text="📚 Knowledge Base Items", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=5)

        # TreeView with scrollbars
        tree_frame = ttk.Frame(left_panel)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree = ttk.Treeview(tree_frame,
                                 columns=("Type", "Name", "Style", "Difficulty", "Source"),
                                 show="tree headings",
                                 yscrollcommand=tree_scroll_y.set,
                                 xscrollcommand=tree_scroll_x.set)

        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_x.config(command=self.tree.xview)

        # Columns
        self.tree.heading("#0", text="ID")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Style", text="Style/Category")
        self.tree.heading("Difficulty", text="Difficulty")
        self.tree.heading("Source", text="Source")

        self.tree.column("#0", width=50)
        self.tree.column("Type", width=100)
        self.tree.column("Name", width=250)
        self.tree.column("Style", width=120)
        self.tree.column("Difficulty", width=100)
        self.tree.column("Source", width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Bind selection
        self.tree.bind('<<TreeviewSelect>>', self.on_item_select)

        # RIGHT PANEL: Details + Stats
        right_panel = ttk.Frame(main_frame, width=500)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))
        right_panel.pack_propagate(False)

        # Stats panel
        stats_frame = ttk.LabelFrame(right_panel, text="📊 Statistics", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))

        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=12, width=50, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True)

        # Details panel
        details_frame = ttk.LabelFrame(right_panel, text="🔍 Item Details", padding=10)
        details_frame.pack(fill=tk.BOTH, expand=True)

        self.details_text = scrolledtext.ScrolledText(details_frame, width=50, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # ==================== STATUS BAR ====================
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def load_knowledge_base(self, path: Path):
        """Load knowledge base JSON"""
        try:
            self.status_bar.config(text=f"Loading: {path.name}...")
            self.root.update()

            stats = self.manager.load_json(path, source_name=path.stem)

            self.status_bar.config(text=f"Loaded: {path.name} - {sum([v for v in stats.values() if isinstance(v, int)])} items")

            self.refresh_view()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load: {e}")
            self.status_bar.config(text="Error loading file")

    def import_json(self):
        """Import single JSON"""
        path = filedialog.askopenfilename(
            title="Select JSON file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if path:
            self.load_knowledge_base(Path(path))

    def import_directory(self):
        """Import all JSON from directory"""
        directory = filedialog.askdirectory(title="Select directory with JSON files")

        if directory:
            try:
                self.status_bar.config(text=f"Loading directory: {Path(directory).name}...")
                self.root.update()

                stats = self.manager.load_directory(Path(directory))

                total_items = sum([v for v in stats.values() if isinstance(v, int)])
                self.status_bar.config(text=f"Loaded: {len(list(Path(directory).glob('*.json')))} files - {total_items} items")

                self.refresh_view()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load directory: {e}")
                self.status_bar.config(text="Error loading directory")

    def export_merged(self):
        """Export merged knowledge base"""
        path = filedialog.asksaveasfilename(
            title="Save merged knowledge base",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="merged_knowledge.json"
        )

        if path:
            try:
                output_path = self.manager.export_merged(Path(path))
                messagebox.showinfo("Success", f"Exported to:\n{output_path}\n\nSize: {output_path.stat().st_size / 1024:.1f} KB")
                self.status_bar.config(text=f"Exported: {output_path.name}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {e}")

    def validate_kb(self):
        """Validate knowledge base"""
        issues = self.manager.validate_knowledge_base()

        msg = f"✅ Validation Complete\n\n"
        msg += f"Errors: {len(issues['errors'])}\n"
        msg += f"Warnings: {len(issues['warnings'])}\n\n"

        if issues['errors']:
            msg += "❌ Errors:\n"
            for error in issues['errors'][:10]:
                msg += f"  - {error}\n"

        if issues['warnings']:
            msg += "\n⚠️  Warnings:\n"
            for warning in issues['warnings'][:10]:
                msg += f"  - {warning}\n"

        messagebox.showinfo("Validation Results", msg)

    def refresh_view(self):
        """Refresh TreeView and stats"""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Get filtered data
        items_to_show = self._get_filtered_items()

        # Populate tree
        for i, item in enumerate(items_to_show):
            item_type = item['_type']
            name = item.get('name', item.get('question_it', item.get('question', 'N/A')))[:50]
            style = item.get('style', item.get('category', 'N/A'))
            difficulty = item.get('difficulty', 'N/A')
            source = item.get('source', 'unknown')

            # Icon based on type
            type_icon = {
                'form': '📋',
                'sequence': '🔄',
                'pattern': '🎯',
                'qa': '💬'
            }.get(item_type, '•')

            self.tree.insert('', tk.END,
                           text=f"{i+1}",
                           values=(f"{type_icon} {item_type}", name, style, difficulty, source),
                           tags=(item_type,))

        # Update stats
        self.update_stats()

        self.status_bar.config(text=f"Showing {len(items_to_show)} items")

    def _get_filtered_items(self) -> List[Dict]:
        """Get items filtered by search and filter dropdown"""
        items = []

        # Collect all items with type tag
        if self.filter_var.get() in ["all", "forms"]:
            for form in self.manager.forms:
                form['_type'] = 'form'
                items.append(form)

        if self.filter_var.get() in ["all", "sequences"]:
            for seq in self.manager.sequences:
                seq['_type'] = 'sequence'
                items.append(seq)

        if self.filter_var.get() in ["all", "patterns"]:
            for pattern in self.manager.patterns:
                pattern['_type'] = 'pattern'
                items.append(pattern)

        if self.filter_var.get() in ["all", "qa_pairs"]:
            for qa in self.manager.qa_pairs:
                qa['_type'] = 'qa'
                items.append(qa)

        # Apply search filter
        search_text = self.search_var.get().lower()
        if search_text:
            filtered = []
            for item in items:
                # Search in name, style, category, question
                searchable = str(item.get('name', ''))
                searchable += str(item.get('style', ''))
                searchable += str(item.get('category', ''))
                searchable += str(item.get('question_it', ''))
                searchable += str(item.get('question', ''))

                if search_text in searchable.lower():
                    filtered.append(item)

            items = filtered

        return items

    def apply_filters(self):
        """Apply search and filter"""
        self.refresh_view()

    def update_stats(self):
        """Update statistics panel"""
        stats = self.manager.get_stats()

        text = "📊 KNOWLEDGE BASE STATS\n"
        text += "=" * 40 + "\n\n"

        text += "📚 Summary:\n"
        for key, value in stats['summary'].items():
            text += f"  • {key}: {value}\n"

        text += f"\n🎨 Styles ({stats['total_styles']}):\n"
        for style, count in sorted(stats['styles'].items(), key=lambda x: x[1], reverse=True)[:8]:
            text += f"  • {style}: {count}\n"

        text += f"\n📈 Difficulties:\n"
        for diff, count in stats['difficulties'].items():
            text += f"  • {diff}: {count}\n"

        text += f"\n🔀 Merge Stats:\n"
        for key, value in stats['merge_stats'].items():
            text += f"  • {key}: {value}\n"

        text += f"\n📂 Sources ({stats['total_sources']}):\n"
        for source in stats['sources'][:8]:
            text += f"  • {source}\n"

        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, text)

    def on_item_select(self, event):
        """Handle item selection in TreeView"""
        selection = self.tree.selection()
        if not selection:
            return

        # Get item index
        item_id = self.tree.item(selection[0], 'text')
        try:
            item_index = int(item_id) - 1
        except:
            return

        # Get item data
        items = self._get_filtered_items()
        if item_index < 0 or item_index >= len(items):
            return

        item = items[item_index]

        # Display details
        details = json.dumps(item, indent=2, ensure_ascii=False)

        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details)


def main():
    """Launch GUI"""
    root = tk.Tk()
    app = KnowledgeBaseGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
