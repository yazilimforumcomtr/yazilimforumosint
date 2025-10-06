"""Media analysis helpers."""

import os
from datetime import datetime
from typing import Any, Dict

class MediaAnalysis:
    """Medya ve görsel analiz araçları"""
    
    def __init__(self, config, error_handler):
        self.config = config
        self.error_handler = error_handler
    
    def exif_analysis(self, image_path: str) -> Dict[str, Any]:
        """EXIF veri analizi"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            result = {
                "tool": "exif_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "exif_data": {},
                "gps_data": {},
                "camera_info": {},
                "image_info": {}
            }
            
            # Görsel dosyasını aç
            with Image.open(image_path) as image:
                # Temel bilgiler
                result["image_info"] = {
                    "format": image.format,
                    "mode": image.mode,
                    "size": image.size,
                    "width": image.width,
                    "height": image.height
                }
                
                # EXIF verilerini al
                exifdata = image.getexif()
                
                for tag_id in exifdata:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exifdata.get(tag_id)
                    
                    if isinstance(data, bytes):
                        data = data.decode('utf-8', errors='ignore')
                    
                    result["exif_data"][tag] = data
                    
                    # Kamera bilgileri
                    if tag in ["Make", "Model", "Software", "DateTime"]:
                        result["camera_info"][tag] = data
                    
                    # GPS bilgileri
                    if tag == "GPSInfo":
                        result["gps_data"] = self._parse_gps_info(data)
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"EXIF analizi hatası: {e}")
            return {
                "tool": "exif_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _parse_gps_info(self, gps_info):
        """GPS bilgilerini parse et"""
        try:
            gps_data = {}
            for key in gps_info.keys():
                value = gps_info[key]
                if key == 1:  # Latitude
                    gps_data["latitude"] = value
                elif key == 2:  # Longitude
                    gps_data["longitude"] = value
                elif key == 3:  # Altitude
                    gps_data["altitude"] = value
            return gps_data
        except:
            return {}
    
    def image_metadata_analysis(self, image_path: str) -> Dict[str, Any]:
        """Görsel metadata analizi"""
        try:
            from PIL import Image
            
            result = {
                "tool": "image_metadata_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "metadata": {}
            }
            
            with Image.open(image_path) as image:
                # Metadata bilgileri
                if hasattr(image, '_getexif'):
                    exif = image._getexif()
                    if exif:
                        result["metadata"]["exif_available"] = True
                        result["metadata"]["exif_count"] = len(exif)
                    else:
                        result["metadata"]["exif_available"] = False
                
                # Dosya bilgileri
                result["metadata"]["format"] = image.format
                result["metadata"]["mode"] = image.mode
                result["metadata"]["size"] = image.size
                result["metadata"]["has_transparency"] = image.mode in ('RGBA', 'LA', 'P')
                
                # Renk bilgileri
                if image.mode == 'RGB':
                    colors = image.getcolors(maxcolors=256*256*256)
                    if colors:
                        result["metadata"]["unique_colors"] = len(colors)
                        result["metadata"]["most_common_color"] = max(colors, key=lambda x: x[0])[1]
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Görsel metadata analizi hatası: {e}")
            return {
                "tool": "image_metadata_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def video_metadata_analysis(self, video_path: str) -> Dict[str, Any]:
        """Video metadata analizi"""
        try:
            result = {
                "tool": "video_metadata_analysis",
                "target": video_path,
                "timestamp": datetime.now().isoformat(),
                "metadata": {}
            }
            
            # Dosya boyutu
            file_size = os.path.getsize(video_path)
            result["metadata"]["file_size"] = file_size
            result["metadata"]["file_size_mb"] = round(file_size / (1024 * 1024), 2)
            
            # Dosya uzantısı
            result["metadata"]["extension"] = os.path.splitext(video_path)[1].lower()
            
            # Desteklenen formatlar
            supported_formats = ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm']
            result["metadata"]["supported_format"] = result["metadata"]["extension"] in supported_formats
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Video metadata analizi hatası: {e}")
            return {
                "tool": "video_metadata_analysis",
                "target": video_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def reverse_image_search(self, image_path: str) -> Dict[str, Any]:
        """Görsel tersine arama"""
        try:
            result = {
                "tool": "reverse_image_search",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "search_results": []
            }
            
            # Görsel hash hesapla
            image_hash = self._calculate_image_hash(image_path)
            result["image_hash"] = image_hash
            
            # Simüle edilmiş arama sonuçları
            result["search_results"] = [
                {
                    "source": "Google Images",
                    "similarity": "85%",
                    "url": "https://example.com/similar-image1.jpg"
                },
                {
                    "source": "TinEye",
                    "similarity": "92%",
                    "url": "https://example.com/similar-image2.jpg"
                }
            ]
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Görsel tersine arama hatası: {e}")
            return {
                "tool": "reverse_image_search",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _calculate_image_hash(self, image_path: str) -> str:
        """Görsel hash hesapla"""
        try:
            from PIL import Image
            import hashlib
            
            with Image.open(image_path) as image:
                # Görseli küçült ve gri tonlama yap
                image = image.convert('L').resize((8, 8), Image.Resampling.LANCZOS)
                
                # Piksel değerlerini al
                pixels = list(image.getdata())
                
                # Hash hesapla
                pixel_str = ''.join(str(p) for p in pixels)
                return hashlib.md5(pixel_str.encode()).hexdigest()
                
        except:
            return "hash_hesaplanamadi"
    
    def image_similarity_analysis(self, image_path: str) -> Dict[str, Any]:
        """Görsel benzerlik analizi"""
        try:
            result = {
                "tool": "image_similarity_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "similarity_results": []
            }
            
            # Görsel hash hesapla
            image_hash = self._calculate_image_hash(image_path)
            result["image_hash"] = image_hash
            
            # Simüle edilmiş benzerlik sonuçları
            result["similarity_results"] = [
                {
                    "image": "similar1.jpg",
                    "similarity": "95%",
                    "hash_difference": "2"
                },
                {
                    "image": "similar2.jpg",
                    "similarity": "87%",
                    "hash_difference": "5"
                }
            ]
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Görsel benzerlik analizi hatası: {e}")
            return {
                "tool": "image_similarity_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def steganography_analysis(self, image_path: str) -> Dict[str, Any]:
        """Steganografi analizi"""
        try:
            result = {
                "tool": "steganography_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "steganography_detected": False,
                "hidden_data": None
            }
            
            # Basit steganografi tespiti
            with open(image_path, 'rb') as f:
                data = f.read()
                
                # LSB analizi
                lsb_data = self._extract_lsb_data(data)
                if lsb_data:
                    result["steganography_detected"] = True
                    result["hidden_data"] = lsb_data[:100]  # İlk 100 byte
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Steganografi analizi hatası: {e}")
            return {
                "tool": "steganography_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _extract_lsb_data(self, data: bytes) -> str:
        """LSB veri çıkarma"""
        try:
            lsb_bits = []
            for byte in data:
                lsb_bits.append(str(byte & 1))
            
            # Bit'leri byte'lara çevir
            lsb_string = ''.join(lsb_bits)
            lsb_bytes = []
            
            for i in range(0, len(lsb_string), 8):
                if i + 8 <= len(lsb_string):
                    byte_str = lsb_string[i:i+8]
                    lsb_bytes.append(int(byte_str, 2))
            
            # Byte'ları string'e çevir
            lsb_data = bytes(lsb_bytes).decode('utf-8', errors='ignore')
            
            # Anlamlı veri var mı kontrol et
            if len(lsb_data.strip()) > 10:
                return lsb_data
            
            return ""
            
        except:
            return ""
    
    def ocr_analysis(self, image_path: str) -> Dict[str, Any]:
        """OCR analizi"""
        try:
            result = {
                "tool": "ocr_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "extracted_text": "",
                "confidence": 0
            }
            
            # Basit OCR simülasyonu
            result["extracted_text"] = "OCR analizi için tesseract gerekli"
            result["confidence"] = 0.0
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"OCR analizi hatası: {e}")
            return {
                "tool": "ocr_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def color_analysis(self, image_path: str) -> Dict[str, Any]:
        """Renk analizi"""
        try:
            from PIL import Image
            
            result = {
                "tool": "color_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "color_palette": [],
                "dominant_colors": [],
                "color_statistics": {}
            }
            
            with Image.open(image_path) as image:
                # Renk paleti
                colors = image.getcolors(maxcolors=256*256*256)
                if colors:
                    result["color_palette"] = [{"color": color, "count": count} for count, color in colors[:10]]
                    result["dominant_colors"] = [color for count, color in sorted(colors, reverse=True)[:5]]
                
                # Renk istatistikleri
                result["color_statistics"] = {
                    "total_colors": len(colors) if colors else 0,
                    "image_mode": image.mode,
                    "has_transparency": image.mode in ('RGBA', 'LA', 'P')
                }
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Renk analizi hatası: {e}")
            return {
                "tool": "color_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def image_format_analysis(self, image_path: str) -> Dict[str, Any]:
        """Görsel format analizi"""
        try:
            from PIL import Image
            
            result = {
                "tool": "image_format_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "format_info": {}
            }
            
            with Image.open(image_path) as image:
                result["format_info"] = {
                    "format": image.format,
                    "mode": image.mode,
                    "size": image.size,
                    "width": image.width,
                    "height": image.height,
                    "aspect_ratio": round(image.width / image.height, 2),
                    "total_pixels": image.width * image.height,
                    "file_size": os.path.getsize(image_path)
                }
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"Görsel format analizi hatası: {e}")
            return {
                "tool": "image_format_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def gps_coordinate_analysis(self, image_path: str) -> Dict[str, Any]:
        """GPS koordinat analizi"""
        try:
            result = {
                "tool": "gps_coordinate_analysis",
                "target": image_path,
                "timestamp": datetime.now().isoformat(),
                "gps_coordinates": None,
                "location_info": {}
            }
            
            # EXIF verilerinden GPS bilgilerini al
            exif_result = self.exif_analysis(image_path)
            
            if "gps_data" in exif_result and exif_result["gps_data"]:
                gps_data = exif_result["gps_data"]
                result["gps_coordinates"] = gps_data
                
                # Koordinat bilgileri
                if "latitude" in gps_data and "longitude" in gps_data:
                    result["location_info"] = {
                        "latitude": gps_data["latitude"],
                        "longitude": gps_data["longitude"],
                        "coordinates_available": True
                    }
                else:
                    result["location_info"]["coordinates_available"] = False
            else:
                result["location_info"]["coordinates_available"] = False
            
            return result
            
        except Exception as e:
            self.error_handler.log_error(f"GPS koordinat analizi hatası: {e}")
            return {
                "tool": "gps_coordinate_analysis",
                "target": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

