<?php

use App\Indicator\emissionA;
use App\Indicator\emissionB;
use App\Indicator\emissionC;
use App\Indicator\emission0;

$melabel = [
	[
		"key" => "cost",
		"label" =>  "Costo per l’azienda al giorno (per tutti i dipendenti) [€]",
		"field_type" => "number",
		"description" => "WIP"
	],
	["key" => "save_company", "label" =>  "Risparmio per l’azienda al giorno (per tutti i dipendenti) [€]", "field_type" => "number", "description" => "WIP"],
	["key" => "save_employee", "label" =>  "Risparmio per il dipendente al giorno [€]", "field_type" => "number", "description" => "WIP"],
];

return [
	'Measures' => [
		101 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che lascia a casa l'auto grazie alla mancanza di sosta", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
					// floatval($series['cost']),
					// floatval($series['save_company']),
					// floatval($series['save_employee']),
				);
				return $a->getOutput();
			},
		],

		157 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che non utilizza l’auto individualmente grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di spostamento con modalità alternative", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					floatval($series['users']),
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					floatval($series['days_cp']) * floatval($series['users']) 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],


		78 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che lascia a casa l'auto grazie alla tariffazione della sosta", "field_type" => "number", "description" => "WIP"],
				["key" => "fee", "label" =>  "Ammontare della tariffa oraria della sosta", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
					// floatval($series['cost']),
					// floatval($series['save_company']),
					// floatval($series['save_employee']),
				);
				return $a->getOutput();
			},
		],

		153 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di carpoolers", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di carpooling", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
				["key" => "equipaggi", "label" =>  "Numero di equipaggi di car pooling", "field_type" => "number", "description" => "WIP"],
				["key" => "stalli", "label" =>  "Numero di stalli dedicati al car pooling", "field_type" => "number", "description" => "WIP"],
				["key" => "min_pax", "label" =>  "Numero minimo passeggeri", "field_type" => "number", "description" => "Numero necessario di utenti per veicolo per usufruire dello stallo riservato"],
			], $melabel),
			'indicator' =>   function ($series) {
				$users = floatval($series['users']);
				$equipaggi = floatval($series['equipaggi']);
				$viaggiPerGiorno = $users > 0 ? $equipaggi / $users : 0.0;
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					$users,
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					$viaggiPerGiorno 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],

		97 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di carpoolers", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di carpooling", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
				["key" => "equipaggi", "label" =>  "Numero di equipaggi di car pooling", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$users = floatval($series['users']);
				$equipaggi = floatval($series['equipaggi']);
				$viaggiPerGiorno = $users > 0 ? $equipaggi / $users : 0.0;
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					$users,
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					$viaggiPerGiorno 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],

		154 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di carpoolers", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di carpooling", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
				["key" => "equipaggi", "label" =>  "Numero di equipaggi di car pooling", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$users = floatval($series['users']);
				$equipaggi = floatval($series['equipaggi']);
				$viaggiPerGiorno = $users > 0 ? $equipaggi / $users : 0.0;
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					$users,
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					$viaggiPerGiorno 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],


		98 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di carpoolers che beneficiano dell’incentivo", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di carpooling", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
				["key" => "equipaggi", "label" =>  "Numero di equipaggi di car pooling", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$users = floatval($series['users']);
				$equipaggi = floatval($series['equipaggi']);
				$viaggiPerGiorno = $users > 0 ? $equipaggi / $users : 0.0;
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					$users,
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					$viaggiPerGiorno 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],

		155 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di carpooling", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
				["key" => "equipaggi", "label" =>  "Numero di equipaggi di car pooling", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$users = floatval($series['users']);
				$equipaggi = floatval($series['equipaggi']);
				$viaggiPerGiorno = $users > 0 ? $equipaggi / $users : 0.0;
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					$users,
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					$viaggiPerGiorno 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],


		104 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di spostamenti in carsharing", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					floatval($series['users']),
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					floatval($series['days_cp']) * floatval($series['users']) 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],

		156 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days_cp", "label" =>  "Giorni/anno di spostamenti in carsharing", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionB(
					floatval($series['days_cp']),
					floatval($series['distance']),
					floatval($series['users']),
					floatval($series['distance']),	//Distanza media percorsa da ogni equipaggio
					floatval($series['days_cp']) * floatval($series['users']) 	//Numero di viaggi al giorno che fa l'equipaggio in sharing rispetto a prima
				);
				return $a->getOutput();
			},
		],

		/** ----------------------------- ASSE 2 ----------------------------------------- */


		95 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		164 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che utilizzano il TPL grazie all'implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		158 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		93 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che utilizzano la navetta", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con la navetta", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
				["key" => "trips", "label" =>  "Numero di viaggi giornalieri della navetta", "field_type" => "number", "description" => "WIP"],
				["key" => "distance-trip", "label" =>  "Km percorsi in ogni viaggio", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionC(
					floatval($series['users']),
					floatval($series['distance']),
					floatval($series['days']),
					floatval($series['trips']),
					floatval($series['distance-trip']),
				);
				return $a->getOutput();
			},
		],

		159 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		160 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		161 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		162 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],



		92 => [
			'labels' => array_merge([
				["key" => "serviti", "label" =>  "Numero dipendenti che sono serviti dalla nuova infrastrtuttura di TPL per lo spostamento casa-lavoro", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di dipendenti che utilizzano la nuova infrastruttura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		163 => [
			'labels' => array_merge([
				["key" => "serviti", "label" =>  "Numero dipendenti che sono serviti dal nuovo servizio di TPL per lo spostamento casa-lavoro", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di dipendenti che utilizzano il nuovo servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con il TPL", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		/*** ------------------------- ASSE 3  ------------------------------ */


		165 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano biciclette o dispositivi di micromobilità", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con biciclette o dispositivi di micromobilità", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],
		
		166 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		171 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano e-bike ", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		167 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "NNumero di dipendenti che acquistano i servizi", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		168 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano biciclette o dispositivi di micromobilità", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con biciclette o dispositivi di micromobilità", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		169 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano e-bike ", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		87 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che beneficiano dell’incentivo", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con bicicletta", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		170 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti aderenti alla community", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con bicicletta", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		84 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che, grazie agli spogliatoi usano la bici", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in bici", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		83 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che, grazie alle aree di sosta, usano la bici", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in bici", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		171 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che, grazie alle aree di sosta, usano la e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		105 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti interessati ad usufruire della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in bici o dispositivi di micromobilità", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		172 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che si sposta in bicicletta o dispositivi di micromobilità grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in bicicletta o dispositivi di micromobilità", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		173 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che si sposta in e-bike grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		174 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che si sposta in cargo-bike grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in cargo-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		90 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti interessati ad usufruire della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti in e-bike", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		175 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con la mobilità condivisa", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		176 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che acquistano l'abbonamento", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con la mobilità condivisa", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		89 => [
			'labels' => array_merge([
				["key" => "serviti", "label" =>  "Numero di dipendenti che sono serviti dal servizio di bike sharing per lo spostamento casa-lavoro", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di dipendenti che, grazie al miglioramento utilizzano il servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con il bike sharing", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		86 => [
			'labels' => array_merge([
				["key" => "serviti", "label" =>  "Numero di dipendenti che sono serviti da infrastrutture pedonali e/o ciclabil per lo spostamento casa-lavoro", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di dipendenti che, grazie al miglioramento utilizzano bici/piedi", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con bici/piedi", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],
		85 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che, grazie alla segnaletica decidono di utilizzare bici/piedi", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con bici/piedi", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],
		177 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che si spostano a piedi/bici grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con bici/piedi", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		/*** ------------------------- ASSE 4  ------------------------------ */

		178 => [
			'labels' => array_merge([
				["key" => "potenziali", "label" =>  "Numero di dipendenti che beneficia dell’iniziativa", "field_type" => "number", "description" => "WIP"],
				["key" => "minutes", "label" =>  "Minuti di flessbilità in ingress/uscita", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di utenti che decidono di lasciare l'auto grazie alla flessibilità", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		77 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di smartworkers", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni di smartworking/anno", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
					// floatval($series['cost']),
					// floatval($series['save_company']),
					// floatval($series['save_employee']),
				);
				return $a->getOutput();
			},
		],


		120 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di coworkers", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni di coworking/anno", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		179 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che si spostano con modalità alternative all’autovettura privata grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		180 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		79 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		80 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],



		81 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		82 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che usufruiscono del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],



		181 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti che riducono l’utilizzo dell’auto privata grazie all’implementazione della misura", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamento con mezzi sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>  function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		/*** ------------------------- ASSE 5  ------------------------------ */


		94 => [
			'labels' => array_merge([
				["key" => "potenziali", "label" =>  "Numero di dipendenti che ricevono informazioni", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di utenti che decidono di lasciare l'auto grazie alle informazioni", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti senz'auto", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		91 => [
			'labels' => array_merge([
				["key" => "potenziali", "label" =>  "Numero di dipendenti coinvolti dagli eventi", "field_type" => "number", "description" => "WIP"],
				["key" => "eventi", "label" =>  "Numero di eventi/anno", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di utenti che decidono di lasciare l'auto grazie agli eventi", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti senz'auto", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

		182 => [
			'labels' => array_merge([
				["key" => "potenziali", "label" =>  "Numero di dipendenti coinvolti dagli eventi", "field_type" => "number", "description" => "WIP"],
				["key" => "eventi", "label" =>  "Numero di eventi/anno", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di utenti che decidono di lasciare l'auto grazie agli eventi", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti senz'auto", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		183 => [
			'labels' => array_merge([
				["key" => "potenziali", "label" =>  "Numero di partecipanti all'iniziativa", "field_type" => "number", "description" => "WIP"],
				["key" => "eventi", "label" =>  "Numero di competizioni/anno", "field_type" => "number", "description" => "WIP"],
				["key" => "users", "label" =>  "Numero di utenti che decidono di lasciare l'auto grazie alla gamification", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti senz'auto", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],


		184 => [
			'labels' => array_merge([
				["key" => "users", "label" =>  "Numero di dipendenti partecipanti all’iniziativa o fruitori del servizio", "field_type" => "number", "description" => "WIP"],
				["key" => "days", "label" =>  "Giorni/anno di spostamenti con modalità sostenibili", "field_type" => "number", "description" => "WIP"],
				["key" => "distance", "label" =>  "Distanza media spostamento casa-lavoro (a/r) [Km]", "field_type" => "number", "description" => "WIP"],
			], $melabel),
			'indicator' =>   function ($series) {
				$a = new emissionA(
					floatval($series['days']),
					floatval($series['users']),
					floatval($series['distance']),
				);
				return $a->getOutput();
			},
		],

	]
];
