import { useState, useEffect } from 'react';
import {
  Mail,
  MapPin,
  Phone,
  Linkedin,
  Github,
  GraduationCap,
  Briefcase,
  Award,
  BookOpen,
  FileText,
  ChevronRight,
  Menu,
  X
} from 'lucide-react';

function App() {
  const [activeSection, setActiveSection] = useState('home');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);

      const sections = ['home', 'about', 'experience', 'education', 'publications', 'skills', 'contact'];
      const current = sections.find(section => {
        const element = document.getElementById(section);
        if (element) {
          const rect = element.getBoundingClientRect();
          return rect.top <= 150 && rect.bottom >= 150;
        }
        return false;
      });
      if (current) setActiveSection(current);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
      setMobileMenuOpen(false);
    }
  };

  const navItems = [
    { id: 'home', label: 'Home' },
    { id: 'about', label: 'About' },
    { id: 'experience', label: 'Experience' },
    { id: 'education', label: 'Education' },
    { id: 'publications', label: 'Publications' },
    { id: 'skills', label: 'Skills' },
    { id: 'contact', label: 'Contact' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-slate-100">
      <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${
        scrolled ? 'bg-white/95 backdrop-blur-sm shadow-lg' : 'bg-transparent'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="text-xl font-bold text-slate-800">Dr. Rahul Sharma</div>

            <div className="hidden md:flex space-x-1">
              {navItems.map(item => (
                <button
                  key={item.id}
                  onClick={() => scrollToSection(item.id)}
                  className={`px-4 py-2 rounded-lg transition-all duration-300 ${
                    activeSection === item.id
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <button
              className="md:hidden p-2"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>

        {mobileMenuOpen && (
          <div className="md:hidden bg-white border-t">
            {navItems.map(item => (
              <button
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                className="block w-full text-left px-6 py-3 hover:bg-slate-50 transition-colors"
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
      </nav>

      <section id="home" className="min-h-screen flex items-center justify-center pt-16 px-4">
        <div className="max-w-6xl w-full grid md:grid-cols-2 gap-12 items-center">
          <div className="space-y-6 opacity-0 animate-slideInLeft">
            <div className="inline-block px-4 py-2 bg-blue-100 text-blue-700 rounded-full text-sm font-semibold">
              Assistant Professor
            </div>
            <h1 className="text-5xl md:text-6xl font-bold text-slate-900 leading-tight">
              Dr. Rahul Sharma
            </h1>
            <p className="text-xl text-slate-600 leading-relaxed">
              Deep Learning & Neuroimaging Specialist | AI Researcher | Academic Leader
            </p>
            <p className="text-lg text-slate-500">
              Assistant Professor at The LNMIIT Jaipur specializing in Deep Learning, Computer Vision, and Alzheimer's Disease Diagnosis
            </p>
            <div className="flex flex-wrap gap-4 pt-4">
              <button
                onClick={() => scrollToSection('contact')}
                className="px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:-translate-y-1"
              >
                Get In Touch
              </button>
              <button
                onClick={() => scrollToSection('publications')}
                className="px-8 py-3 bg-white text-blue-600 rounded-lg hover:bg-slate-50 transition-all duration-300 shadow-lg hover:shadow-xl border-2 border-blue-600"
              >
                View Publications
              </button>
            </div>
          </div>

          <div className="flex justify-center opacity-0 animate-slideInRight">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-br from-blue-400 to-blue-600 rounded-2xl transform rotate-6"></div>
              <img
                src="/PP.jpeg"
                alt="Dr. Rahul Sharma"
                className="relative rounded-2xl shadow-2xl w-80 h-80 object-cover border-8 border-white"
              />
            </div>
          </div>
        </div>
      </section>

      <section id="about" className="py-20 px-4 bg-white">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-12 text-slate-900">About Me</h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2">
              <div className="bg-blue-600 w-12 h-12 rounded-lg flex items-center justify-center mb-4">
                <GraduationCap className="text-white" size={24} />
              </div>
              <h3 className="text-xl font-bold mb-2 text-slate-900">Education</h3>
              <p className="text-slate-600">Ph.D. from NIT Silchar in Deep Learning & Neuroimaging with extensive research experience</p>
            </div>

            <div className="p-6 bg-gradient-to-br from-green-50 to-green-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2">
              <div className="bg-green-600 w-12 h-12 rounded-lg flex items-center justify-center mb-4">
                <Briefcase className="text-white" size={24} />
              </div>
              <h3 className="text-xl font-bold mb-2 text-slate-900">Experience</h3>
              <p className="text-slate-600">10+ years of teaching experience and research in AI, Deep Learning, and Computer Vision</p>
            </div>

            <div className="p-6 bg-gradient-to-br from-orange-50 to-orange-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2">
              <div className="bg-orange-600 w-12 h-12 rounded-lg flex items-center justify-center mb-4">
                <Award className="text-white" size={24} />
              </div>
              <h3 className="text-xl font-bold mb-2 text-slate-900">Research</h3>
              <p className="text-slate-600">12+ journal publications and multiple conference papers in top-tier venues</p>
            </div>
          </div>
        </div>
      </section>

      <section id="experience" className="py-20 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-12 text-slate-900">Professional Experience</h2>

          <div className="space-y-6">
            <div className="bg-white p-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 border-l-4 border-blue-600">
              <div className="flex items-start gap-4">
                <div className="bg-blue-100 p-3 rounded-lg">
                  <Briefcase className="text-blue-600" size={24} />
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-slate-900">Assistant Professor</h3>
                  <p className="text-blue-600 font-semibold">The LNMIIT Jaipur</p>
                  <p className="text-slate-500 mb-3">July 2024 – Present</p>
                  <p className="text-slate-600 mb-2">Department of Communication and Computer Engineering</p>
                  <div className="flex flex-wrap gap-2 mt-3">
                    <span className="px-3 py-1 bg-blue-50 text-blue-700 rounded-full text-sm">Computer Organization</span>
                    <span className="px-3 py-1 bg-blue-50 text-blue-700 rounded-full text-sm">IoT</span>
                    <span className="px-3 py-1 bg-blue-50 text-blue-700 rounded-full text-sm">Deep Learning</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 border-l-4 border-green-600">
              <div className="flex items-start gap-4">
                <div className="bg-green-100 p-3 rounded-lg">
                  <BookOpen className="text-green-600" size={24} />
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-slate-900">Research Associate</h3>
                  <p className="text-green-600 font-semibold">Indian Institute of Technology Indore</p>
                  <p className="text-slate-500 mb-3">May 2023 – November 2023</p>
                  <p className="text-slate-600">NSM project: "Diagnosis of Alzheimer's disease using brain imaging data"</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 border-l-4 border-orange-600">
              <div className="flex items-start gap-4">
                <div className="bg-orange-100 p-3 rounded-lg">
                  <Briefcase className="text-orange-600" size={24} />
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-slate-900">Assistant Professor</h3>
                  <p className="text-orange-600 font-semibold">SSIPMT Raipur</p>
                  <p className="text-slate-500 mb-3">February 2024 – July 2024</p>
                  <p className="text-slate-600">Department of Electronics and Telecommunication Engineering</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="education" className="py-20 px-4 bg-white">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-12 text-slate-900">Education</h2>

          <div className="space-y-6">
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <div className="flex items-start gap-4">
                <div className="bg-blue-600 p-3 rounded-lg">
                  <GraduationCap className="text-white" size={28} />
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-slate-900">Ph.D. in Electronics and Communication</h3>
                  <p className="text-blue-700 font-semibold text-lg">National Institute of Technology Silchar</p>
                  <p className="text-slate-600 mb-2">July 2019 – January 2024</p>
                  <p className="text-slate-700 font-semibold">CPI: 8.46</p>
                  <p className="text-slate-600 mt-3"><strong>Thesis:</strong> Deep Learning Based Alzheimer Disease Diagnosis Using Neuroimaging Data</p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-green-50 to-green-100 p-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <div className="flex items-start gap-4">
                <div className="bg-green-600 p-3 rounded-lg">
                  <GraduationCap className="text-white" size={28} />
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-slate-900">M.Tech. in Electronics and Communication</h3>
                  <p className="text-green-700 font-semibold text-lg">CSVTU Bhilai</p>
                  <p className="text-slate-600 mb-2">2012 – 2016</p>
                  <p className="text-slate-700 font-semibold">Percentage: 72.27%</p>
                  <p className="text-slate-600 mt-3"><strong>Specialization:</strong> Communication and Signal Processing</p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-orange-50 to-orange-100 p-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <div className="flex items-start gap-4">
                <div className="bg-orange-600 p-3 rounded-lg">
                  <GraduationCap className="text-white" size={28} />
                </div>
                <div className="flex-1">
                  <h3 className="text-2xl font-bold text-slate-900">B.Tech. in Electronics and Communication</h3>
                  <p className="text-orange-700 font-semibold text-lg">CSVTU Bhilai</p>
                  <p className="text-slate-600 mb-2">2007 – 2011</p>
                  <p className="text-slate-700 font-semibold">Percentage: 64.85%</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="publications" className="py-20 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-12 text-slate-900">Research Publications</h2>

          <div className="bg-white p-8 rounded-xl shadow-xl mb-8">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
              <div className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg">
                <p className="text-4xl font-bold text-blue-600">12+</p>
                <p className="text-slate-600 mt-2">Journal Articles</p>
              </div>
              <div className="p-6 bg-gradient-to-br from-green-50 to-green-100 rounded-lg">
                <p className="text-4xl font-bold text-green-600">5+</p>
                <p className="text-slate-600 mt-2">Conference Papers</p>
              </div>
              <div className="p-6 bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg">
                <p className="text-4xl font-bold text-orange-600">1</p>
                <p className="text-slate-600 mt-2">Patent</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h3 className="text-2xl font-bold text-slate-900 mb-4 flex items-center gap-2">
              <FileText className="text-blue-600" />
              Selected Publications
            </h3>

            <div className="bg-white p-6 rounded-lg shadow-lg hover:shadow-xl transition-all duration-300 border-l-4 border-blue-600">
              <p className="text-slate-700 leading-relaxed">
                <strong>M. Tanveer, T. Goel, R. Sharma, et al.</strong>, "Ensemble deep learning for alzheimer's disease characterization and estimation," <em>Nature Mental Health</em>, vol. 2, no. 6, pp. 655–667, 2024.
              </p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-lg hover:shadow-xl transition-all duration-300 border-l-4 border-green-600">
              <p className="text-slate-700 leading-relaxed">
                <strong>R. Sharma, T. Goel, M. Tanveer, C. T. Lin, and R. Murugan</strong>, "Deep-learning-based diagnosis and prognosis of alzheimer's disease: A comprehensive review," <em>IEEE Transactions on Cognitive and Developmental Systems</em>, vol. 15, no. 3, pp. 1123–1138, 2023.
              </p>
            </div>

            <div className="bg-white p-6 rounded-lg shadow-lg hover:shadow-xl transition-all duration-300 border-l-4 border-orange-600">
              <p className="text-slate-700 leading-relaxed">
                <strong>R. Sharma, M. Al-Dhaifallah, and A. Shakoor</strong>, "Fusenet: Attention-learning based mri–pet slice fusion for alzheimer's diagnosis," <em>Computers and Electrical Engineering</em>, vol. 127, p. 110 556, 2025.
              </p>
            </div>

            <div className="bg-gradient-to-r from-orange-50 to-orange-100 p-6 rounded-lg shadow-lg border-l-4 border-orange-600 mt-6">
              <h4 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <Award className="text-orange-600" size={20} />
                Patent
              </h4>
              <p className="text-slate-700">
                <strong>R. Sharma, T. Goel, R. Khosla, and R. Murugan</strong>, "System for the early detection of Alzheimer's disease," German Patent, App. No. 202023100083.5, IPC: G16H 50/20, 2023.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section id="skills" className="py-20 px-4 bg-white">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-12 text-slate-900">Skills & Expertise</h2>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <h3 className="text-xl font-bold mb-4 text-slate-900">Programming</h3>
              <div className="flex flex-wrap gap-2">
                <span className="px-3 py-1 bg-blue-600 text-white rounded-full text-sm">Python</span>
                <span className="px-3 py-1 bg-blue-600 text-white rounded-full text-sm">MATLAB</span>
              </div>
            </div>

            <div className="p-6 bg-gradient-to-br from-green-50 to-green-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <h3 className="text-xl font-bold mb-4 text-slate-900">Neuroimaging Tools</h3>
              <div className="flex flex-wrap gap-2">
                <span className="px-3 py-1 bg-green-600 text-white rounded-full text-sm">SPM</span>
                <span className="px-3 py-1 bg-green-600 text-white rounded-full text-sm">Freesurfer</span>
                <span className="px-3 py-1 bg-green-600 text-white rounded-full text-sm">FSL</span>
                <span className="px-3 py-1 bg-green-600 text-white rounded-full text-sm">ANTs</span>
              </div>
            </div>

            <div className="p-6 bg-gradient-to-br from-orange-50 to-orange-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <h3 className="text-xl font-bold mb-4 text-slate-900">Data Handling</h3>
              <div className="flex flex-wrap gap-2">
                <span className="px-3 py-1 bg-orange-600 text-white rounded-full text-sm">NIfTI Scans</span>
                <span className="px-3 py-1 bg-orange-600 text-white rounded-full text-sm">MRI</span>
                <span className="px-3 py-1 bg-orange-600 text-white rounded-full text-sm">PET</span>
              </div>
            </div>

            <div className="p-6 bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <h3 className="text-xl font-bold mb-4 text-slate-900">Languages</h3>
              <div className="flex flex-wrap gap-2">
                <span className="px-3 py-1 bg-purple-600 text-white rounded-full text-sm">English</span>
                <span className="px-3 py-1 bg-purple-600 text-white rounded-full text-sm">Hindi</span>
              </div>
            </div>

            <div className="p-6 bg-gradient-to-br from-pink-50 to-pink-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <h3 className="text-xl font-bold mb-4 text-slate-900">Teaching</h3>
              <div className="flex flex-wrap gap-2">
                <span className="px-3 py-1 bg-pink-600 text-white rounded-full text-sm">Deep Learning</span>
                <span className="px-3 py-1 bg-pink-600 text-white rounded-full text-sm">IoT</span>
                <span className="px-3 py-1 bg-pink-600 text-white rounded-full text-sm">Computer Org</span>
              </div>
            </div>

            <div className="p-6 bg-gradient-to-br from-cyan-50 to-cyan-100 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300">
              <h3 className="text-xl font-bold mb-4 text-slate-900">Other</h3>
              <div className="flex flex-wrap gap-2">
                <span className="px-3 py-1 bg-cyan-600 text-white rounded-full text-sm">LaTeX</span>
                <span className="px-3 py-1 bg-cyan-600 text-white rounded-full text-sm">Research</span>
                <span className="px-3 py-1 bg-cyan-600 text-white rounded-full text-sm">Training</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="contact" className="py-20 px-4">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-4xl font-bold text-center mb-12 text-slate-900">Get In Touch</h2>

          <div className="grid md:grid-cols-2 gap-8">
            <div className="space-y-6">
              <div className="bg-white p-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 flex items-start gap-4">
                <div className="bg-blue-100 p-3 rounded-lg">
                  <Mail className="text-blue-600" size={24} />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 mb-1">Email</h3>
                  <a href="mailto:sharmarahul.26dec@gmail.com" className="text-blue-600 hover:text-blue-700">
                    sharmarahul.26dec@gmail.com
                  </a>
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 flex items-start gap-4">
                <div className="bg-green-100 p-3 rounded-lg">
                  <Phone className="text-green-600" size={24} />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 mb-1">Phone</h3>
                  <a href="tel:+919827834360" className="text-green-600 hover:text-green-700">
                    +91 98278 34360
                  </a>
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 flex items-start gap-4">
                <div className="bg-orange-100 p-3 rounded-lg">
                  <MapPin className="text-orange-600" size={24} />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 mb-1">Location</h3>
                  <p className="text-slate-600">
                    A8-F, Akshat Kanota Estate<br />
                    Kanota Nayla Road<br />
                    Jaipur, Rajasthan 303012, India
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <div className="bg-gradient-to-br from-blue-600 to-blue-700 p-8 rounded-xl shadow-lg text-white">
                <h3 className="text-2xl font-bold mb-4">Connect Online</h3>
                <div className="space-y-4">
                  <a
                    href="https://linkedin.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-3 p-4 bg-white/10 rounded-lg hover:bg-white/20 transition-all duration-300"
                  >
                    <Linkedin size={24} />
                    <span>LinkedIn Profile</span>
                    <ChevronRight className="ml-auto" size={20} />
                  </a>

                  <a
                    href="https://github.com/simplyishu"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-3 p-4 bg-white/10 rounded-lg hover:bg-white/20 transition-all duration-300"
                  >
                    <Github size={24} />
                    <span>@simplyishu</span>
                    <ChevronRight className="ml-auto" size={20} />
                  </a>

                  <a
                    href="https://scholar.google.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-3 p-4 bg-white/10 rounded-lg hover:bg-white/20 transition-all duration-300"
                  >
                    <BookOpen size={24} />
                    <span>Google Scholar</span>
                    <ChevronRight className="ml-auto" size={20} />
                  </a>
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg">
                <h3 className="text-xl font-bold text-slate-900 mb-3">Certifications</h3>
                <ul className="space-y-2 text-slate-600">
                  <li className="flex items-start gap-2">
                    <Award className="text-blue-600 mt-1 flex-shrink-0" size={18} />
                    <span>Data Science Masters - PWskills (2023)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <Award className="text-blue-600 mt-1 flex-shrink-0" size={18} />
                    <span>IEEE CIS Summer School - IIT Indore (2022)</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      <footer className="bg-slate-900 text-white py-8 px-4">
        <div className="max-w-6xl mx-auto text-center">
          <p className="text-slate-400">
            © 2024 Dr. Rahul Sharma. All rights reserved.
          </p>
          <p className="text-slate-500 mt-2 text-sm">
            Assistant Professor | Deep Learning Researcher | AI Specialist
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
