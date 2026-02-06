# comparison_engine.py
"""
🎓 AI_MODULE: Comparison Engine for Martial Arts
🎓 AI_DESCRIPTION: Confronta tecniche tra diversi maestri e stili
🎓 AI_BUSINESS: Identifica best practices e variazioni per training ottimale
🎓 AI_TEACHING: DTW (Dynamic Time Warping) per confronto sequenze temporali

🔄 ALTERNATIVE_VALUTATE:
- Frame-by-frame comparison: Scartato, troppo rigido per movimenti fluidi
- Neural network similarity: Scartato, richiede troppi dati training
- Manual annotation: Scartato, 10 ore per confronto

💡 PERCHÉ_QUESTA_SOLUZIONE:
- DTW permette confronto anche con velocità diverse
- Metriche multiple per analisi completa
- Visualizzazione differenze chiare per utenti
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.spatial.distance import euclidean, cosine
from fastdtw import fastdtw
import cv2

@dataclass
class ComparisonResult:
    """Risultato di un confronto tra tecniche"""
    technique_name: str
    master1: str
    master2: str
    overall_similarity: float
    timing_similarity: float
    form_similarity: float
    power_similarity: float
    key_differences: List[Dict]
    recommendations: List[str]
    timestamp: str

@dataclass
class TechniqueVariation:
    """Variazione di una tecnica tra maestri"""
    variation_point: str
    timestamp: float
    description: str
    severity: str  # 'minor', 'moderate', 'major'
    
class ComparisonEngine:
    """
    Motore di confronto per tecniche di arti marziali
    """
    
    def __init__(self, knowledge_base_path: str = "knowledge_base"):
        """
        Inizializza comparison engine
        
        Args:
            knowledge_base_path: Path al knowledge base
        """
        self.kb_path = Path(knowledge_base_path)
        self.kb_path.mkdir(exist_ok=True)
        
        # Cache per tecniche caricate
        self.techniques_cache = {}
        
        # Soglie per classificazione differenze
        self.thresholds = {
            'minor': 0.85,      # Similarity > 85% = differenza minore
            'moderate': 0.70,   # 70-85% = differenza moderata
            'major': 0.50       # < 70% = differenza maggiore
        }
        
    def compare_techniques(
        self,
        technique1_data: Dict,
        technique2_data: Dict,
        comparison_mode: str = 'detailed'
    ) -> ComparisonResult:
        """
        Confronta due esecuzioni della stessa tecnica
        
        Args:
            technique1_data: Dati prima tecnica
            technique2_data: Dati seconda tecnica
            comparison_mode: 'quick' o 'detailed'
            
        Returns:
            ComparisonResult con analisi completa
        """
        # Estrai skeleton data
        skeleton1 = self._extract_skeleton_sequence(technique1_data)
        skeleton2 = self._extract_skeleton_sequence(technique2_data)
        
        # Allinea sequenze temporalmente
        aligned_s1, aligned_s2 = self._align_sequences(skeleton1, skeleton2)
        
        # Calcola metriche di similarità
        timing_sim = self._calculate_timing_similarity(
            technique1_data.get('duration', 0),
            technique2_data.get('duration', 0)
        )
        
        form_sim = self._calculate_form_similarity(aligned_s1, aligned_s2)
        
        power_sim = self._calculate_power_similarity(
            technique1_data.get('motion_signature', ''),
            technique2_data.get('motion_signature', '')
        )
        
        # Overall similarity (media pesata)
        overall_sim = (
            timing_sim * 0.2 +
            form_sim * 0.5 +
            power_sim * 0.3
        )
        
        # Identifica differenze chiave
        key_differences = []
        if comparison_mode == 'detailed':
            key_differences = self._identify_key_differences(
                aligned_s1,
                aligned_s2,
                technique1_data,
                technique2_data
            )
        
        # Genera raccomandazioni
        recommendations = self._generate_recommendations(
            overall_sim,
            timing_sim,
            form_sim,
            power_sim,
            key_differences
        )
        
        return ComparisonResult(
            technique_name=technique1_data.get('name', 'unknown'),
            master1=technique1_data.get('master', 'master1'),
            master2=technique2_data.get('master', 'master2'),
            overall_similarity=overall_sim,
            timing_similarity=timing_sim,
            form_similarity=form_sim,
            power_similarity=power_sim,
            key_differences=key_differences,
            recommendations=recommendations,
            timestamp=datetime.now().isoformat()
        )
    
    def compare_multiple_masters(
        self,
        technique_name: str,
        masters_data: Dict[str, Dict],
        reference_master: Optional[str] = None
    ) -> Dict:
        """
        Confronta la stessa tecnica tra multipli maestri
        
        Args:
            technique_name: Nome della tecnica
            masters_data: Dict con dati per ogni maestro
            reference_master: Maestro di riferimento (se None, usa consenso)
            
        Returns:
            Analisi comparativa completa
        """
        if len(masters_data) < 2:
            raise ValueError("Servono almeno 2 maestri per il confronto")
        
        # Se non specificato, trova il "consenso" come riferimento
        if reference_master is None:
            reference_master = self._find_consensus_master(masters_data)
        
        reference_data = masters_data[reference_master]
        
        # Confronta ogni maestro con il riferimento
        comparisons = {}
        for master_name, master_data in masters_data.items():
            if master_name != reference_master:
                comparison = self.compare_techniques(
                    reference_data,
                    master_data,
                    comparison_mode='detailed'
                )
                comparisons[master_name] = comparison
        
        # Calcola statistiche aggregate
        avg_similarity = np.mean([c.overall_similarity for c in comparisons.values()])
        std_similarity = np.std([c.overall_similarity for c in comparisons.values()])
        
        # Identifica variazioni comuni
        common_variations = self._identify_common_variations(comparisons)
        
        # Crea matrice di similarità tra tutti i maestri
        similarity_matrix = self._create_similarity_matrix(masters_data)
        
        return {
            'technique_name': technique_name,
            'reference_master': reference_master,
            'num_masters': len(masters_data),
            'average_similarity': avg_similarity,
            'similarity_std': std_similarity,
            'individual_comparisons': comparisons,
            'common_variations': common_variations,
            'similarity_matrix': similarity_matrix,
            'consensus_form': self._extract_consensus_form(masters_data)
        }
    
    def _extract_skeleton_sequence(self, technique_data: Dict) -> np.ndarray:
        """
        Estrae sequenza skeleton dai dati tecnica
        
        Args:
            technique_data: Dati della tecnica
            
        Returns:
            Array numpy con sequenza skeleton
        """
        if 'skeleton_data' in technique_data:
            return np.array(technique_data['skeleton_data'])
        
        # Fallback: usa key_poses se skeleton completo non disponibile
        if 'key_poses' in technique_data:
            key_poses = technique_data['key_poses']
            # Interpola tra key poses per sequenza smooth
            return self._interpolate_key_poses(key_poses)
        
        # Se non ci sono dati, ritorna array vuoto
        return np.array([])
    
    def _interpolate_key_poses(self, key_poses: List[Dict], num_frames: int = 30) -> np.ndarray:
        """
        Interpola tra key poses per creare sequenza smooth
        
        Args:
            key_poses: Lista di pose chiave
            num_frames: Numero frame target
            
        Returns:
            Sequenza interpolata
        """
        if not key_poses:
            return np.array([])
        
        # Converti poses in array numpy
        poses_array = []
        for pose in key_poses:
            # Flatten pose dictionary in array
            pose_vector = []
            for body_part, points in pose.items():
                if isinstance(points, list):
                    for point in points:
                        if isinstance(point, list):
                            pose_vector.extend(point)
            poses_array.append(pose_vector)
        
        poses_array = np.array(poses_array)
        
        if len(poses_array) == 0:
            return np.array([])
        
        # Interpola linearmente tra poses
        interpolated = []
        frames_per_segment = num_frames // (len(poses_array) - 1)
        
        for i in range(len(poses_array) - 1):
            start_pose = poses_array[i]
            end_pose = poses_array[i + 1]
            
            for j in range(frames_per_segment):
                alpha = j / frames_per_segment
                interp_pose = start_pose * (1 - alpha) + end_pose * alpha
                interpolated.append(interp_pose)
        
        # Aggiungi ultima pose
        interpolated.append(poses_array[-1])
        
        return np.array(interpolated)
    
    def _align_sequences(
        self,
        seq1: np.ndarray,
        seq2: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Allinea due sequenze temporalmente usando DTW
        
        Args:
            seq1: Prima sequenza
            seq2: Seconda sequenza
            
        Returns:
            Sequenze allineate
        """
        if len(seq1) == 0 or len(seq2) == 0:
            return seq1, seq2
        
        # Dynamic Time Warping per allineamento
        distance, path = fastdtw(seq1, seq2, dist=euclidean)
        
        # Allinea sequenze secondo path DTW
        aligned_seq1 = []
        aligned_seq2 = []
        
        for idx1, idx2 in path:
            aligned_seq1.append(seq1[idx1])
            aligned_seq2.append(seq2[idx2])
        
        return np.array(aligned_seq1), np.array(aligned_seq2)
    
    def _calculate_timing_similarity(self, duration1: float, duration2: float) -> float:
        """
        Calcola similarità temporale
        
        Args:
            duration1: Durata prima tecnica
            duration2: Durata seconda tecnica
            
        Returns:
            Score similarità (0-1)
        """
        if duration1 == 0 or duration2 == 0:
            return 0.0
        
        # Ratio delle durate
        ratio = min(duration1, duration2) / max(duration1, duration2)
        
        # Penalizza differenze maggiori
        if ratio > 0.9:
            return 1.0
        elif ratio > 0.8:
            return 0.9
        elif ratio > 0.7:
            return 0.75
        else:
            return ratio
    
    def _calculate_form_similarity(
        self,
        aligned_s1: np.ndarray,
        aligned_s2: np.ndarray
    ) -> float:
        """
        Calcola similarità della forma/postura
        
        Args:
            aligned_s1: Prima sequenza allineata
            aligned_s2: Seconda sequenza allineata
            
        Returns:
            Score similarità (0-1)
        """
        if len(aligned_s1) == 0 or len(aligned_s2) == 0:
            return 0.0
        
        # Calcola distanza frame-by-frame
        distances = []
        for frame1, frame2 in zip(aligned_s1, aligned_s2):
            # Usa cosine similarity per invarianza a scala
            if np.linalg.norm(frame1) > 0 and np.linalg.norm(frame2) > 0:
                sim = 1 - cosine(frame1, frame2)
                distances.append(sim)
        
        if not distances:
            return 0.0
        
        # Media delle similarità
        return np.mean(distances)
    
    def _calculate_power_similarity(
        self,
        signature1: str,
        signature2: str
    ) -> float:
        """
        Calcola similarità della potenza/energia del movimento
        
        Args:
            signature1: Motion signature prima tecnica
            signature2: Motion signature seconda tecnica
            
        Returns:
            Score similarità (0-1)
        """
        if not signature1 or not signature2:
            return 0.5  # Default se mancano dati
        
        # Converti signatures in vettori numerici
        vec1 = [ord(c) for c in signature1[:min(len(signature1), len(signature2))]]
        vec2 = [ord(c) for c in signature2[:min(len(signature1), len(signature2))]]
        
        if not vec1 or not vec2:
            return 0.5
        
        # Calcola correlazione
        correlation = np.corrcoef(vec1, vec2)[0, 1]
        
        # Normalizza in range 0-1
        return (correlation + 1) / 2
    
    def _identify_key_differences(
        self,
        aligned_s1: np.ndarray,
        aligned_s2: np.ndarray,
        data1: Dict,
        data2: Dict
    ) -> List[Dict]:
        """
        Identifica le differenze principali tra due tecniche
        
        Args:
            aligned_s1: Prima sequenza allineata
            aligned_s2: Seconda sequenza allineata
            data1: Dati completi prima tecnica
            data2: Dati completi seconda tecnica
            
        Returns:
            Lista di differenze identificate
        """
        differences = []
        
        if len(aligned_s1) == 0 or len(aligned_s2) == 0:
            return differences
        
        # Analizza per segmenti
        segment_size = max(1, len(aligned_s1) // 10)
        
        for i in range(0, len(aligned_s1), segment_size):
            segment1 = aligned_s1[i:i+segment_size]
            segment2 = aligned_s2[i:i+segment_size]
            
            if len(segment1) > 0 and len(segment2) > 0:
                # Calcola differenza media nel segmento
                segment_diff = np.mean([
                    np.linalg.norm(f1 - f2)
                    for f1, f2 in zip(segment1, segment2)
                ])
                
                # Se differenza significativa
                if segment_diff > 0.3:  # Threshold
                    # Identifica tipo di differenza
                    diff_type = self._classify_difference(
                        segment1,
                        segment2,
                        i / len(aligned_s1)  # Posizione relativa
                    )
                    
                    differences.append({
                        'timestamp': i / len(aligned_s1),
                        'type': diff_type,
                        'severity': self._calculate_severity(segment_diff),
                        'description': self._generate_diff_description(
                            diff_type,
                            data1.get('master', 'Master1'),
                            data2.get('master', 'Master2')
                        )
                    })
        
        return differences
    
    def _classify_difference(
        self,
        segment1: np.ndarray,
        segment2: np.ndarray,
        relative_position: float
    ) -> str:
        """
        Classifica il tipo di differenza
        
        Args:
            segment1: Primo segmento
            segment2: Secondo segmento
            relative_position: Posizione relativa (0-1)
            
        Returns:
            Tipo di differenza
        """
        # Analizza caratteristiche del movimento
        velocity1 = np.std(segment1, axis=0).mean()
        velocity2 = np.std(segment2, axis=0).mean()
        
        if abs(velocity1 - velocity2) > 0.2:
            return 'speed_variation'
        
        # Analizza ampiezza movimento
        range1 = np.ptp(segment1, axis=0).mean()
        range2 = np.ptp(segment2, axis=0).mean()
        
        if abs(range1 - range2) > 0.3:
            return 'amplitude_variation'
        
        # Posizione nel movimento
        if relative_position < 0.3:
            return 'opening_variation'
        elif relative_position > 0.7:
            return 'closing_variation'
        else:
            return 'core_variation'
    
    def _calculate_severity(self, difference_value: float) -> str:
        """
        Calcola severità della differenza
        
        Args:
            difference_value: Valore differenza
            
        Returns:
            'minor', 'moderate', o 'major'
        """
        if difference_value < 0.2:
            return 'minor'
        elif difference_value < 0.4:
            return 'moderate'
        else:
            return 'major'
    
    def _generate_diff_description(
        self,
        diff_type: str,
        master1: str,
        master2: str
    ) -> str:
        """
        Genera descrizione leggibile della differenza
        
        Args:
            diff_type: Tipo di differenza
            master1: Nome primo maestro
            master2: Nome secondo maestro
            
        Returns:
            Descrizione testuale
        """
        descriptions = {
            'speed_variation': f"{master1} esegue il movimento più velocemente di {master2}",
            'amplitude_variation': f"{master1} ha movimenti più ampi rispetto a {master2}",
            'opening_variation': f"Differenza nell'apertura della tecnica tra {master1} e {master2}",
            'closing_variation': f"Differenza nella chiusura della tecnica tra {master1} e {master2}",
            'core_variation': f"Variazione nella parte centrale del movimento tra {master1} e {master2}"
        }
        
        return descriptions.get(diff_type, f"Differenza tra {master1} e {master2}")
    
    def _generate_recommendations(
        self,
        overall_sim: float,
        timing_sim: float,
        form_sim: float,
        power_sim: float,
        differences: List[Dict]
    ) -> List[str]:
        """
        Genera raccomandazioni basate sul confronto
        
        Args:
            overall_sim: Similarità generale
            timing_sim: Similarità temporale
            form_sim: Similarità forma
            power_sim: Similarità potenza
            differences: Lista differenze
            
        Returns:
            Lista di raccomandazioni
        """
        recommendations = []
        
        # Raccomandazioni su timing
        if timing_sim < 0.8:
            recommendations.append(
                "Presta attenzione al ritmo: le due esecuzioni hanno tempi molto diversi. "
                "Prova a rallentare o accelerare per trovare il tuo ritmo ottimale."
            )
        
        # Raccomandazioni su forma
        if form_sim < 0.7:
            recommendations.append(
                "Differenze significative nella forma. Studia attentamente le posizioni chiave "
                "e confronta frame by frame per migliorare l'accuratezza."
            )
        elif form_sim < 0.85:
            recommendations.append(
                "Buona esecuzione generale, ma ci sono piccole differenze nella forma. "
                "Concentrati sui dettagli per perfezionare la tecnica."
            )
        
        # Raccomandazioni su potenza
        if power_sim < 0.7:
            recommendations.append(
                "Pattern di energia diversi. Osserva come viene distribuita la forza "
                "durante il movimento e cerca di mantenere un flusso costante."
            )
        
        # Raccomandazioni specifiche per differenze
        major_diffs = [d for d in differences if d.get('severity') == 'major']
        if major_diffs:
            recommendations.append(
                f"Identificate {len(major_diffs)} differenze maggiori. "
                "Concentrati su questi punti specifici per allineare la tua esecuzione."
            )
        
        # Raccomandazione generale
        if overall_sim > 0.9:
            recommendations.append(
                "Eccellente esecuzione! Le tecniche sono molto simili. "
                "Continua a praticare per mantenere questa qualità."
            )
        elif overall_sim > 0.75:
            recommendations.append(
                "Buona padronanza della tecnica con margini di miglioramento. "
                "Focus sui dettagli identificati per raggiungere l'eccellenza."
            )
        else:
            recommendations.append(
                "Differenze significative nell'esecuzione. Considera di studiare "
                "entrambe le interpretazioni per capire quale si adatta meglio al tuo stile."
            )
        
        return recommendations
    
    def _find_consensus_master(self, masters_data: Dict[str, Dict]) -> str:
        """
        Trova il maestro più rappresentativo del consenso
        
        Args:
            masters_data: Dati di tutti i maestri
            
        Returns:
            Nome del maestro consenso
        """
        # Calcola similarità media di ogni maestro con tutti gli altri
        avg_similarities = {}
        
        for master1 in masters_data:
            similarities = []
            for master2 in masters_data:
                if master1 != master2:
                    sim = self._quick_similarity(
                        masters_data[master1],
                        masters_data[master2]
                    )
                    similarities.append(sim)
            
            avg_similarities[master1] = np.mean(similarities)
        
        # Ritorna maestro con similarità media più alta
        return max(avg_similarities, key=avg_similarities.get)
    
    def _quick_similarity(self, data1: Dict, data2: Dict) -> float:
        """
        Calcolo rapido di similarità per consenso
        
        Args:
            data1: Dati prima tecnica
            data2: Dati seconda tecnica
            
        Returns:
            Score similarità veloce
        """
        # Usa solo duration e signature per velocità
        duration_sim = self._calculate_timing_similarity(
            data1.get('duration', 0),
            data2.get('duration', 0)
        )
        
        signature_sim = self._calculate_power_similarity(
            data1.get('motion_signature', ''),
            data2.get('motion_signature', '')
        )
        
        return (duration_sim + signature_sim) / 2
    
    def _identify_common_variations(
        self,
        comparisons: Dict[str, ComparisonResult]
    ) -> List[Dict]:
        """
        Identifica variazioni comuni tra maestri
        
        Args:
            comparisons: Risultati confronti
            
        Returns:
            Lista variazioni comuni
        """
        # Raggruppa differenze per tipo e timestamp
        all_differences = {}
        
        for master, comparison in comparisons.items():
            for diff in comparison.key_differences:
                key = (diff['type'], round(diff['timestamp'], 1))
                if key not in all_differences:
                    all_differences[key] = []
                all_differences[key].append(master)
        
        # Trova differenze presenti in più maestri
        common_variations = []
        for (diff_type, timestamp), masters in all_differences.items():
            if len(masters) >= len(comparisons) / 2:  # Presente in almeno metà
                common_variations.append({
                    'type': diff_type,
                    'timestamp': timestamp,
                    'masters_affected': masters,
                    'frequency': len(masters) / len(comparisons)
                })
        
        return sorted(common_variations, key=lambda x: x['frequency'], reverse=True)
    
    def _create_similarity_matrix(self, masters_data: Dict[str, Dict]) -> np.ndarray:
        """
        Crea matrice di similarità tra tutti i maestri
        
        Args:
            masters_data: Dati di tutti i maestri
            
        Returns:
            Matrice di similarità
        """
        masters = list(masters_data.keys())
        n = len(masters)
        matrix = np.ones((n, n))
        
        for i in range(n):
            for j in range(i+1, n):
                sim = self._quick_similarity(
                    masters_data[masters[i]],
                    masters_data[masters[j]]
                )
                matrix[i, j] = sim
                matrix[j, i] = sim
        
        return matrix
    
    def _extract_consensus_form(self, masters_data: Dict[str, Dict]) -> Dict:
        """
        Estrae la forma consensus dalla media dei maestri
        
        Args:
            masters_data: Dati di tutti i maestri
            
        Returns:
            Forma consensus mediata
        """
        # Estrai tutte le sequenze skeleton
        all_skeletons = []
        for data in masters_data.values():
            skeleton = self._extract_skeleton_sequence(data)
            if len(skeleton) > 0:
                all_skeletons.append(skeleton)
        
        if not all_skeletons:
            return {}
        
        # Trova lunghezza media
        avg_length = int(np.mean([len(s) for s in all_skeletons]))
        
        # Ridimensiona tutti alla stessa lunghezza
        resized_skeletons = []
        for skeleton in all_skeletons:
            resized = cv2.resize(skeleton, (skeleton.shape[1], avg_length))
            resized_skeletons.append(resized)
        
        # Calcola media
        consensus_skeleton = np.mean(resized_skeletons, axis=0)
        
        return {
            'skeleton_data': consensus_skeleton.tolist(),
            'num_masters': len(all_skeletons),
            'avg_length': avg_length
        }
    
    def visualize_comparison(
        self,
        comparison_result: ComparisonResult,
        output_path: Optional[str] = None
    ):
        """
        Visualizza risultati del confronto
        
        Args:
            comparison_result: Risultati da visualizzare
            output_path: Path per salvare immagine (opzionale)
        """
        fig, axes = plt.subplots(2, 2, figsize=(12, 8))
        fig.suptitle(f'Confronto: {comparison_result.technique_name}', fontsize=16)
        
        # Grafico similarità
        ax1 = axes[0, 0]
        metrics = ['Overall', 'Timing', 'Form', 'Power']
        values = [
            comparison_result.overall_similarity,
            comparison_result.timing_similarity,
            comparison_result.form_similarity,
            comparison_result.power_similarity
        ]
        colors = ['green' if v > 0.8 else 'orange' if v > 0.6 else 'red' for v in values]
        ax1.bar(metrics, values, color=colors)
        ax1.set_ylim(0, 1)
        ax1.set_ylabel('Similarity Score')
        ax1.set_title('Metriche di Similarità')
        
        # Timeline differenze
        ax2 = axes[0, 1]
        if comparison_result.key_differences:
            timestamps = [d['timestamp'] for d in comparison_result.key_differences]
            severities = [
                3 if d['severity'] == 'major' else 2 if d['severity'] == 'moderate' else 1
                for d in comparison_result.key_differences
            ]
            ax2.scatter(timestamps, severities, c=severities, cmap='RdYlGn_r', s=100)
            ax2.set_xlabel('Timeline (0-1)')
            ax2.set_ylabel('Severity')
            ax2.set_yticks([1, 2, 3])
            ax2.set_yticklabels(['Minor', 'Moderate', 'Major'])
        ax2.set_title('Timeline Differenze')
        
        # Distribuzione differenze per tipo
        ax3 = axes[1, 0]
        if comparison_result.key_differences:
            diff_types = {}
            for diff in comparison_result.key_differences:
                diff_type = diff['type']
                diff_types[diff_type] = diff_types.get(diff_type, 0) + 1
            
            ax3.pie(diff_types.values(), labels=diff_types.keys(), autopct='%1.1f%%')
        ax3.set_title('Tipi di Differenze')
        
        # Raccomandazioni
        ax4 = axes[1, 1]
        ax4.axis('off')
        recommendations_text = '\n\n'.join(comparison_result.recommendations[:3])
        ax4.text(0.1, 0.9, 'Raccomandazioni:', fontsize=12, fontweight='bold',
                transform=ax4.transAxes, verticalalignment='top')
        ax4.text(0.1, 0.7, recommendations_text, fontsize=10,
                transform=ax4.transAxes, verticalalignment='top', wrap=True)
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path)
        else:
            plt.show()
    
    def save_comparison_results(
        self,
        comparison_result: ComparisonResult,
        output_dir: Optional[str] = None
    ):
        """
        Salva risultati confronto
        
        Args:
            comparison_result: Risultati da salvare
            output_dir: Directory output (default: knowledge_base/comparisons)
        """
        if output_dir is None:
            output_dir = self.kb_path / 'comparisons'
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True, parents=True)
        
        # Nome file con timestamp
        filename = f"comparison_{comparison_result.technique_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = output_path / filename
        
        # Converti in dict e salva
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(asdict(comparison_result), f, indent=2, ensure_ascii=False)
        
        print(f"Risultati salvati in: {filepath}")


# Esempio di utilizzo
if __name__ == '__main__':
    # Inizializza engine
    engine = ComparisonEngine()
    
    # Dati esempio per due tecniche
    technique1 = {
        'name': 'white_crane_spreads_wings',
        'master': 'Chen Xiaowang',
        'duration': 5.2,
        'motion_signature': 'abc123def456',
        'skeleton_data': [],  # Normalmente contiene dati skeleton
        'key_poses': []  # Pose chiave
    }
    
    technique2 = {
        'name': 'white_crane_spreads_wings',
        'master': 'Yang Jun',
        'duration': 6.1,
        'motion_signature': 'abc456def789',
        'skeleton_data': [],
        'key_poses': []
    }
    
    # Confronta tecniche
    result = engine.compare_techniques(technique1, technique2)
    
    # Stampa risultati
    print(f"Similarità generale: {result.overall_similarity:.1%}")
    print(f"Differenze identificate: {len(result.key_differences)}")
    for rec in result.recommendations:
        print(f"- {rec}")
    
    # Salva risultati
    engine.save_comparison_results(result)
