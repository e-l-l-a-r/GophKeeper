// Package main предоставляет мультичекер staticlint, инструмент для статического анализа кода Go.
//
// Анализаторы, включенные в этот мультичекер:
//
// 1. Все стандартные анализаторы из пакета golang.org/x/tools/go/analysis/passes:
//   - asmdecl: сообщает о несоответствиях между файлами ассемблера и объявлениями Go.
//   - assign: проверяет наличие бесполезных присваиваний.
//   - atomic: проверяет наличие распространенных ошибок при использовании пакета sync/atomic.
//   - atomicalign: проверяет наличие невыровненных по 64-битной границе аргументов функций sync/atomic.
//   - bools: проверяет наличие распространенных ошибок, связанных с логическими операторами.
//   - buildssa: строит форму SSA для использования последующими анализаторами.
//   - buildtag: проверяет, что теги +build правильно сформированы и корректно расположены.
//   - cgocall: проверяет наличие нарушений правил передачи указателей cgo.
//   - composite: проверяет наличие неключевых составных литералов.
//   - copylock: проверяет наличие блокировок, ошибочно переданных по значению.
//   - ctrlflow: предоставляет граф потока управления для других анализаторов.
//   - deepequalerrors: проверяет использование reflect.DeepEqual с объектами ошибок.
//   - errorsas: проверяет, что второй аргумент errors.As является указателем на тип, реализующий error.
//   - fieldalignment: проверяет наличие полей структур, которые можно переупорядочить для экономии места.
//   - findcall: находит вызовы определенных функций (используется для пользовательского анализа).
//   - framepointer: сообщает об ассемблерном коде, который портит указатель кадра.
//   - httpresponse: проверяет наличие ошибок при использовании HTTP-ответов.
//   - ifaceassert: проверяет наличие невозможных утверждений типов интерфейс-интерфейс.
//   - inspect: предоставляет инспектор AST для других анализаторов.
//   - loopclosure: проверяет наличие ссылок на переменные цикла из вложенных функций.
//   - lostcancel: проверяет отсутствие вызова функции отмены контекста.
//   - nilfunc: проверяет наличие бесполезных сравнений функций с nil.
//   - nilness: сообщает о затененном nil в логических выражениях.
//   - pkgfact: предоставляет механизм для сериализации и десериализации фактов пакета.
//   - printf: проверяет согласованность строк формата Printf и аргументов.
//   - reflectvaluecompare: проверяет наличие сравнений между reflect.Value и значениями интерфейса.
//   - shadow: проверяет наличие затененных переменных.
//   - shift: проверяет наличие сдвигов, превышающих разрядность целого числа.
//   - sigchanyzer: проверяет наличие небуферизованных каналов сигналов.
//   - sortslice: проверяет вызовы sort.Slice, которые не используют тип среза.
//   - stdmethods: проверяет сигнатуры методов со стандартными именами.
//   - stringintconv: проверяет преобразования string(int).
//   - structtag: проверяет соответствие тегов полей структур reflect.StructTag.Get.
//   - testinggoroutine: проверяет вызовы Fatal из горутины, запущенной тестом.
//   - tests: проверяет наличие распространенных ошибок в функциях тестов и бенчмарков.
//   - unmarshal: проверяет передачу значений, не являющихся указателями или интерфейсами, в функции размаршаливания.
//   - unreachable: проверяет наличие недостижимого кода.
//   - unsafeptr: проверяет наличие неверных преобразований uintptr в unsafe.Pointer.
//   - unusedresult: проверяет отсутствие использования результатов вызовов определенных функций.
//   - unusedwrite: проверяет наличие неиспользуемых записей в поля структур или переменные.
//   - usesgenerics: проверяет использование общих функций (generics).
//
// 2. Все анализаторы класса SA из staticcheck.io (Staticcheck):
//   - SA*: Анализаторы для проверки корректности, безопасности и производительности.
//
// 3. Выбранные анализаторы из других классов staticcheck.io:
//   - S1000: Использование обычной отправки или приёма из канала вместо select с одним случаем.
//   - S1002: Пропуск сравнения с логической константой.
//   - S1005: Отказ от лишнего пустого идентификатора.
//   - S1008: Упрощение возврата логического выражения.
//   - S1009: Пропуск лишней проверки на nil для срезов, карт и каналов.
//   - S1011: Объединение двух срезов одним вызовом append.
//   - S1016: Использование преобразования типа вместо ручного копирования полей структуры.
//   - S1021: Объединение объявления переменной и присваивания.
//   - S1025: Отказ от лишнего fmt.Sprintf("%s", x).
//   - S1039: Отказ от лишнего вызова fmt.Sprint.
//   - ST1000: Неверная или отсутствующая документация пакета.
//   - ST1005: Неверное форматирование строк ошибок.
//   - QF1001: Применение закона Де Моргана.
//
// 4. Публичные анализаторы:
//   - nilerr (github.com/gostaticanalysis/nilerr): находит код, который возвращает nil, даже если ошибка не равна nil.
//   - errcheck (github.com/kisielk/errcheck): находит непроверенные ошибки в коде.
//
// 5. Пользовательский анализатор:
//   - osexitanalyzer: запрещает прямые вызовы os.Exit в функции main пакета main.
package main

import (
	"strings"

	"github.com/gostaticanalysis/nilerr"
	"github.com/kisielk/errcheck/errcheck"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/multichecker"
	"golang.org/x/tools/go/analysis/passes/asmdecl"
	"golang.org/x/tools/go/analysis/passes/assign"
	"golang.org/x/tools/go/analysis/passes/atomic"
	"golang.org/x/tools/go/analysis/passes/atomicalign"
	"golang.org/x/tools/go/analysis/passes/bools"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/buildtag"
	"golang.org/x/tools/go/analysis/passes/cgocall"
	"golang.org/x/tools/go/analysis/passes/composite"
	"golang.org/x/tools/go/analysis/passes/copylock"
	"golang.org/x/tools/go/analysis/passes/ctrlflow"
	"golang.org/x/tools/go/analysis/passes/deepequalerrors"
	"golang.org/x/tools/go/analysis/passes/errorsas"
	"golang.org/x/tools/go/analysis/passes/fieldalignment"
	"golang.org/x/tools/go/analysis/passes/findcall"
	"golang.org/x/tools/go/analysis/passes/framepointer"
	"golang.org/x/tools/go/analysis/passes/httpresponse"
	"golang.org/x/tools/go/analysis/passes/ifaceassert"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/analysis/passes/loopclosure"
	"golang.org/x/tools/go/analysis/passes/lostcancel"
	"golang.org/x/tools/go/analysis/passes/nilfunc"
	"golang.org/x/tools/go/analysis/passes/nilness"
	"golang.org/x/tools/go/analysis/passes/pkgfact"
	"golang.org/x/tools/go/analysis/passes/printf"
	"golang.org/x/tools/go/analysis/passes/reflectvaluecompare"
	"golang.org/x/tools/go/analysis/passes/shadow"
	"golang.org/x/tools/go/analysis/passes/shift"
	"golang.org/x/tools/go/analysis/passes/sigchanyzer"
	"golang.org/x/tools/go/analysis/passes/sortslice"
	"golang.org/x/tools/go/analysis/passes/stdmethods"
	"golang.org/x/tools/go/analysis/passes/stringintconv"
	"golang.org/x/tools/go/analysis/passes/structtag"
	"golang.org/x/tools/go/analysis/passes/testinggoroutine"
	"golang.org/x/tools/go/analysis/passes/tests"
	"golang.org/x/tools/go/analysis/passes/unmarshal"
	"golang.org/x/tools/go/analysis/passes/unreachable"
	"golang.org/x/tools/go/analysis/passes/unsafeptr"
	"golang.org/x/tools/go/analysis/passes/unusedresult"
	"golang.org/x/tools/go/analysis/passes/unusedwrite"
	"golang.org/x/tools/go/analysis/passes/usesgenerics"
	"honnef.co/go/tools/quickfix"
	"honnef.co/go/tools/simple"
	"honnef.co/go/tools/staticcheck"
	"honnef.co/go/tools/stylecheck"

	"github.com/e-l-l-a-r/gophkeeper/cmd/staticlint/osexitanalyzer"
)

func main() {
	analyzers := []*analysis.Analyzer{
		// Стандартные анализаторы
		asmdecl.Analyzer,
		assign.Analyzer,
		atomic.Analyzer,
		atomicalign.Analyzer,
		bools.Analyzer,
		buildssa.Analyzer,
		buildtag.Analyzer,
		cgocall.Analyzer,
		composite.Analyzer,
		copylock.Analyzer,
		ctrlflow.Analyzer,
		deepequalerrors.Analyzer,
		errorsas.Analyzer,
		fieldalignment.Analyzer,
		findcall.Analyzer,
		framepointer.Analyzer,
		httpresponse.Analyzer,
		ifaceassert.Analyzer,
		inspect.Analyzer,
		loopclosure.Analyzer,
		lostcancel.Analyzer,
		nilfunc.Analyzer,
		nilness.Analyzer,
		pkgfact.Analyzer,
		printf.Analyzer,
		reflectvaluecompare.Analyzer,
		shadow.Analyzer,
		shift.Analyzer,
		sigchanyzer.Analyzer,
		sortslice.Analyzer,
		stdmethods.Analyzer,
		stringintconv.Analyzer,
		structtag.Analyzer,
		testinggoroutine.Analyzer,
		tests.Analyzer,
		unmarshal.Analyzer,
		unreachable.Analyzer,
		unsafeptr.Analyzer,
		unusedresult.Analyzer,
		unusedwrite.Analyzer,
		usesgenerics.Analyzer,

		// Пользовательский анализатор
		osexitanalyzer.Analyzer,

		// Публичные анализаторы
		nilerr.Analyzer,
		errcheck.Analyzer,
	}

	// Анализаторы staticcheck SA
	for _, v := range staticcheck.Analyzers {
		if strings.HasPrefix(v.Analyzer.Name, "SA") {
			analyzers = append(analyzers, v.Analyzer)
		}
	}

	// Анализаторы staticcheck (S, ST, QF)
	// Выбранные анализаторы класса S, упрощающие код.
	simpleChecks := map[string]bool{
		"S1000": true, // Использование обычной отправки или приёма из канала вместо select с одним случаем
		"S1002": true, // Пропуск сравнения с логической константой
		"S1005": true, // Отказ от лишнего пустого идентификатора
		"S1008": true, // Упрощение возврата логического выражения
		"S1009": true, // Пропуск лишней проверки на nil для срезов, карт и каналов
		"S1011": true, // Объединение двух срезов одним вызовом append
		"S1016": true, // Использование преобразования типа вместо ручного копирования полей структуры
		"S1021": true, // Объединение объявления переменной и присваивания
		"S1025": true, // Отказ от лишнего fmt.Sprintf("%s", x)
		"S1039": true, // Отказ от лишнего вызова fmt.Sprint
	}
	for _, v := range simple.Analyzers {
		if simpleChecks[v.Analyzer.Name] {
			analyzers = append(analyzers, v.Analyzer)
		}
	}
	for _, v := range stylecheck.Analyzers {
		// Неверная или отсутствующая документация пакета, форматирование строк ошибок
		if v.Analyzer.Name == "ST1000" || v.Analyzer.Name == "ST1005" {
			analyzers = append(analyzers, v.Analyzer)
		}
	}
	for _, v := range quickfix.Analyzers {
		if v.Analyzer.Name == "QF1001" { // Применение закона Де Моргана
			analyzers = append(analyzers, v.Analyzer)
			break
		}
	}

	multichecker.Main(analyzers...)
}
